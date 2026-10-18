import { afterEach, describe, expect, it } from 'vitest';

import {
  FAKE_WEB_URL,
  fakeAgentApprovals,
  fakeGraphQL,
  lookups,
  type OperationHandler,
  withoutLookups,
} from '../../test/helpers/fake-graphql.js';
import { connectTools, type Harness, textOf } from '../../test/helpers/tool-harness.js';
import { BugSecureError } from '../errors.js';

/** triage:write, plus profile:read for the staff check. */
const TRIAGER = ['triage:write', 'profile:read'] as const;

const posted = (isInternal: boolean) => ({
  addReportComment: { id: 'c9', reportId: 'r1', isInternal, createdAt: '2026-09-21T10:00:00.000Z' },
});

const api = (comment: OperationHandler, overrides: Record<string, OperationHandler> = {}) => {
  const approvals = fakeAgentApprovals('approve');
  return {
    approvals,
    graphql: fakeGraphQL({ ...lookups(), ...approvals.handlers, AddTriageComment: comment, ...overrides }),
  };
};

let harness: Harness | undefined;
afterEach(async () => {
  await harness?.close();
  harness = undefined;
});

describe('add_triage_comment', () => {
  it('registers an organization-only (internal) note by default, and says so in the message', async () => {
    const { graphql, approvals } = api(() => posted(true));
    harness = await connectTools({ graphql, grantedScopes: [...TRIAGER], viewerId: 'triager-1' });

    const result = await harness.call('add_triage_comment', {
      reportId: 'r1',
      content: 'Likely dupe.',
    });

    expect(result.isError).toBeFalsy();
    const input = { reportId: 'r1', content: 'Likely dupe.', isInternal: true };
    expect(approvals.created[0]?.parts).toEqual([{ operation: 'addReportComment', arguments: { input } }]);
    expect(withoutLookups(graphql.calls)).toEqual([
      {
        operation: 'AddTriageComment',
        variables: { input, clientRequestId: approvals.created[0]?.clientRequestId },
      },
    ]);
    expect(result.structuredContent).toMatchObject({ comment: { id: 'c9', internal: true } });
    expect(harness.prompts[0]?.url).toBe(`${FAKE_WEB_URL}/agent-approvals/${approvals.created[0]?.id ?? ''}`);
    expect(harness.prompts[0]?.message).toContain('add an internal note to a report, as your organisation');
    expect(harness.prompts[0]?.message).not.toContain('Likely dupe.');
  });

  it('posts to the researcher only with visibleToResearcher: true, said in the message', async () => {
    const { graphql, approvals } = api(() => posted(false));
    harness = await connectTools({ graphql, grantedScopes: [...TRIAGER], viewerId: 'triager-1' });

    const result = await harness.call('add_triage_comment', {
      reportId: 'r1',
      content: 'Thanks, reproducing.',
      visibleToResearcher: true,
    });

    expect(approvals.created[0]?.parts[0]?.arguments).toMatchObject({ input: { isInternal: false } });
    expect(withoutLookups(graphql.calls)[0]?.variables).toMatchObject({ input: { isInternal: false } });
    expect(result.structuredContent).toMatchObject({ comment: { internal: false } });
    expect(harness.prompts[0]?.message).toContain(
      'post a comment the researcher sees on a report, as your organisation',
    );
  });

  it('sends nothing when the user does not open the review page', async () => {
    const { graphql, approvals } = api(() => posted(true));
    harness = await connectTools({
      graphql,
      grantedScopes: [...TRIAGER],
      viewerId: 'triager-1',
      open: 'decline',
    });

    const result = await harness.call('add_triage_comment', { reportId: 'r1', content: 'x' });
    expect(result.isError).toBe(true);
    expect(approvals.created).toHaveLength(1);
    expect(withoutLookups(graphql.calls)).toHaveLength(0);
  });

  it('rejects invalid arguments before registering anything', async () => {
    const graphql = fakeGraphQL({});
    harness = await connectTools({ graphql, grantedScopes: [...TRIAGER], viewerId: 'triager-1' });

    expect((await harness.call('add_triage_comment', { reportId: 'r1', content: '' })).isError).toBe(true);
    expect(
      (await harness.call('add_triage_comment', { reportId: 'r1', content: 'x', visibleToResearcher: 'yes' }))
        .isError,
    ).toBe(true);
    expect(graphql.calls).toHaveLength(0);
  });

  it('explains an organization that has not opted in to AI triage access', async () => {
    const { graphql } = api(() => {
      throw new BugSecureError(
        'ORG_AI_ACCESS_DISABLED',
        'This organization has not enabled AI triage access.',
      );
    });
    harness = await connectTools({ graphql, grantedScopes: [...TRIAGER], viewerId: 'triager-1' });

    expect(textOf(await harness.call('add_triage_comment', { reportId: 'r1', content: 'hi' }))).toContain(
      'AI triage access',
    );
  });

  it('refuses a BugSecure staff account before registering anything', async () => {
    const { graphql, approvals } = api(() => posted(true), lookups({ roles: ['PLATFORM_ROLE_A'] }));
    harness = await connectTools({ graphql, grantedScopes: [...TRIAGER], viewerId: 'triager-1' });
    const result = await harness.call('add_triage_comment', { reportId: 'r1', content: 'hi' });
    expect(result.isError).toBe(true);
    expect(textOf(result)).toContain('BugSecure staff role;');
    expect(harness.prompts).toHaveLength(0);
    expect(approvals.created).toEqual([]);
    expect(withoutLookups(graphql.calls)).toEqual([]);
  });

  it('refuses the user’s own report (it would post as the researcher), pointing at add_report_comment', async () => {
    const { graphql, approvals } = api(() => posted(true), lookups({ reporterId: 'triager-1' }));
    harness = await connectTools({
      graphql,
      grantedScopes: [...TRIAGER, 'triage:read'],
      viewerId: 'triager-1',
    });
    const result = await harness.call('add_triage_comment', { reportId: 'r1', content: 'hi' });
    expect(result.isError).toBe(true);
    expect(textOf(result)).toContain('add_report_comment');
    expect(approvals.created).toEqual([]);
  });

  it('refuses when it could post on either side and cannot read the report to tell which', async () => {
    const { graphql, approvals } = api(() => posted(true));
    harness = await connectTools({
      graphql,
      grantedScopes: [...TRIAGER, 'reports:write'],
      viewerId: 'triager-1',
    });
    const result = await harness.call('add_triage_comment', { reportId: 'r1', content: 'hi' });
    expect(result.isError).toBe(true);
    expect(textOf(result)).toMatch(
      /^Nothing was sent: this connection can comment as a researcher and as an organisation/,
    );
    expect(textOf(result)).toContain('Grant triage:read');
    expect(approvals.created).toEqual([]);
    expect(withoutLookups(graphql.calls)).toEqual([]);
  });

  it('makes no lookup under the other side’s read scope, which shows none of the organisation’s reports', async () => {
    // reports:read alone reads the user's own reports: the API answers every report of their
    // organisations with a refusal, so a lookup under it could only refuse the note outright. The
    // API checks whose report it is when the note is posted.
    const { graphql } = api(() => posted(true));
    harness = await connectTools({
      graphql,
      grantedScopes: [...TRIAGER, 'reports:read'],
      viewerId: 'triager-1',
    });
    const result = await harness.call('add_triage_comment', { reportId: 'r1', content: 'hi' });
    expect(result.isError).toBeFalsy();
    expect(graphql.calls.map((c) => c.operation)).not.toContain('GetReportRef');
  });

  it('refuses, asking for triage:read, when it could post on either side and holds only reports:read', async () => {
    const { graphql, approvals } = api(() => posted(true));
    harness = await connectTools({
      graphql,
      grantedScopes: [...TRIAGER, 'reports:write', 'reports:read'],
      viewerId: 'triager-1',
    });
    const result = await harness.call('add_triage_comment', { reportId: 'r1', content: 'hi' });
    expect(result.isError).toBe(true);
    expect(textOf(result)).toContain('Grant triage:read');
    expect(approvals.created).toEqual([]);
    expect(graphql.calls.map((c) => c.operation)).not.toContain('GetReportRef');
    expect(withoutLookups(graphql.calls)).toEqual([]);
  });
});
