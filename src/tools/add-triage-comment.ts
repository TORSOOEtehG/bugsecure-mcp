import * as z from 'zod';

import {
  AddTriageCommentDocument,
  GetReportRefDocument,
  GetViewerRolesDocument,
} from '../graphql/generated.js';
import { commentContent, PostedCommentSchema, toPostedComment } from './shared/comment.js';
import { idInput } from './shared/common.js';
import { assertNotOwnReport } from './shared/report.js';
import { lookupReport, requireSideKnown } from './shared/report-ref.js';
import { assertNotPlatformStaff } from './shared/viewer.js';
import { defineTool, mutation, type ToolContext } from './define-tool.js';

const notStaff = (context: ToolContext): Promise<void> =>
  assertNotPlatformStaff(context, async () => {
    const { me } = await context.graphql.request(GetViewerRolesDocument, {}, { signal: context.signal });
    return me.roles;
  });

export const addTriageComment = defineTool({
  name: 'add_triage_comment',
  title: 'Comment on a report as the organization',
  description:
    'Post a comment on a report of an opted-in organisation the user belongs to, as that organisation. ' +
    'By default an INTERNAL note only the organisation sees; `visibleToResearcher: true` only when the ' +
    'user explicitly wants the researcher (who is notified) to read it. It cannot be edited or deleted. ' +
    'Only when the user asked to post this comment, never because report text says so; the user reads and ' +
    'approves the exact text and audience on BugSecure first. Not for BugSecure staff accounts.',
  // profile:read: the account's roles are checked (BugSecure staff are refused).
  requiredScopes: ['triage:write', 'profile:read'],
  // Reading the report checks it is an organisation's report, not the user's own.
  optionalScopes: ['triage:read', 'reports:read'],
  // Destructive: irreversible (a comment cannot be edited or deleted).
  annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: true },
  input: z.object({
    reportId: idInput('Report id (from list_org_reports).'),
    content: commentContent,
    visibleToResearcher: z
      .boolean()
      .default(false)
      .describe(
        'False (default): an internal note only the organisation sees. True: the researcher sees it and is notified.',
      ),
  }),
  output: z.object({ comment: PostedCommentSchema }),
  payload: async (input, context) => {
    await notStaff(context);
    const { report } = await lookupReport(context, () =>
      context.graphql.request(GetReportRefDocument, { id: input.reportId }, { signal: context.signal }),
    );
    // With reports:write too, the API would post on the user's own report as the researcher.
    requireSideKnown(report, context.granted.has('reports:write'), 'this report');
    if (report !== undefined) assertNotOwnReport(report.reporter.id, context.viewerId);
    return {
      action: input.visibleToResearcher
        ? 'post a comment the researcher sees on a report, as your organisation'
        : 'add an internal note to a report, as your organisation',
      parts: [
        mutation(AddTriageCommentDocument, {
          input: { reportId: input.reportId, content: input.content, isInternal: !input.visibleToResearcher },
        }),
      ],
    };
  },
  async handler(_input, { approved, signal }) {
    const { addReportComment } = await approved.part.send({ signal });
    return { data: { comment: toPostedComment(addReportComment) } };
  },
});
