import { afterEach, describe, expect, it } from 'vitest';

import {
  FAKE_WEB_URL,
  fakeAgentApprovals,
  fakeGraphQL,
  idempotentWrite,
  lookups,
  type OperationHandler,
  REQUEST_ID,
  withoutLookups,
} from '../../test/helpers/fake-graphql.js';
import { connectTools, type Harness, textOf } from '../../test/helpers/tool-harness.js';
import { BugSecureError } from '../errors.js';

const posted = { id: 'c9', reportId: 'r1', isInternal: false, createdAt: '2026-09-21T10:00:00.000Z' };

const api = (handlers: Record<string, OperationHandler> = {}) => {
  const approvals = fakeAgentApprovals('approve');
  return {
    approvals,
    graphql: fakeGraphQL({
      ...approvals.handlers,
      AddReportComment: () => ({ addReportComment: posted }),
      ...handlers,
    }),
  };
};

let harness: Harness | undefined;
afterEach(async () => {
  await harness?.close();
  harness = undefined;
});

describe('add_report_comment', () => {
  it('registers the exact comment for review, then posts it as the researcher', async () => {
    const { graphql, approvals } = api();
    harness = await connectTools({ graphql, grantedScopes: ['reports:write'] });

    const result = await harness.call('add_report_comment', {
      reportId: 'r1',
      content: ' Here is the account. ',
    });

    expect(result.isError).toBeFalsy();
    const input = { reportId: 'r1', content: 'Here is the account.', isInternal: false };
    expect(approvals.created[0]?.parts).toEqual([{ operation: 'addReportComment', arguments: { input } }]);
    expect(harness.prompts[0]?.url).toBe(`${FAKE_WEB_URL}/agent-approvals/${approvals.created[0]?.id ?? ''}`);
    expect(harness.prompts[0]?.message).toContain(
      'wants to comment on one of your reports, as the researcher',
    );
    expect(harness.prompts[0]?.message).not.toContain('Here is the account.');
    expect(withoutLookups(graphql.calls)).toEqual([
      {
        operation: 'AddReportComment',
        variables: { input, clientRequestId: approvals.created[0]?.clientRequestId },
      },
    ]);
    expect(result.structuredContent).toEqual({
      comment: { id: 'c9', reportId: 'r1', internal: false, createdAt: posted.createdAt },
    });
  });

  it('never accepts an internal flag from the researcher side', async () => {
    const { graphql, approvals } = api();
    harness = await connectTools({ graphql, grantedScopes: ['reports:write'] });

    await harness.call('add_report_comment', {
      reportId: 'r1',
      content: 'hi',
      internal: true,
      isInternal: true,
    });
    expect(approvals.created[0]?.parts[0]?.arguments).toMatchObject({ input: { isInternal: false } });
    expect(withoutLookups(graphql.calls)[0]?.variables).toMatchObject({ input: { isInternal: false } });
  });

  it('rejects invalid arguments before registering anything', async () => {
    const graphql = fakeGraphQL({});
    harness = await connectTools({ graphql, grantedScopes: ['reports:write'] });

    expect((await harness.call('add_report_comment', { reportId: 'r1', content: '   ' })).isError).toBe(true);
    expect(
      (await harness.call('add_report_comment', { reportId: 'r1', content: 'x'.repeat(10_001) })).isError,
    ).toBe(true);
    expect((await harness.call('add_report_comment', { content: 'hi' })).isError).toBe(true);
    expect(graphql.calls).toHaveLength(0);
  });

  it('turns an insufficient-scope API error into actionable guidance', async () => {
    const { graphql } = api({
      AddReportComment: () => {
        throw new BugSecureError('INSUFFICIENT_SCOPE', 'missing permission', {
          requiredScopes: ['reports:write', 'triage:write'],
        });
      },
    });
    harness = await connectTools({ graphql, grantedScopes: ['reports:write'] });

    expect(textOf(await harness.call('add_report_comment', { reportId: 'r1', content: 'hi' }))).toContain(
      'login --scopes "reports:write triage:write"',
    );
  });

  it('posts only on the user’s own report, checked before registering anything', async () => {
    const { graphql, approvals } = api(lookups({ reporterId: 'someone-else' }));
    harness = await connectTools({ graphql, grantedScopes: ['reports:write', 'reports:read'] });
    const result = await harness.call('add_report_comment', { reportId: 'r1', content: 'hi' });
    expect(result.isError).toBe(true);
    expect(textOf(result)).toContain('not one of your own reports');
    expect(harness.prompts).toHaveLength(0);
    expect(approvals.created).toEqual([]);
    expect(withoutLookups(graphql.calls)).toEqual([]);
  });

  it('checks whose report it is and posts on the user’s own report', async () => {
    const { graphql } = api(lookups());
    harness = await connectTools({ graphql, grantedScopes: ['reports:write', 'reports:read'] });
    expect((await harness.call('add_report_comment', { reportId: 'r1', content: 'hi' })).isError).toBeFalsy();
    expect(graphql.calls.map((c) => c.operation)).toContain('GetReportRef');
  });

  it('refuses when it could post on either side and cannot read the report to tell which', async () => {
    const { graphql, approvals } = api();
    harness = await connectTools({ graphql, grantedScopes: ['reports:write', 'triage:write'] });
    const result = await harness.call('add_report_comment', { reportId: 'r1', content: 'hi' });
    expect(result.isError).toBe(true);
    expect(textOf(result)).toContain('Grant reports:read');
    expect(approvals.created).toEqual([]);
    expect(graphql.calls).toEqual([]);
  });

  it('makes no lookup under the other side’s read scope, which shows none of the user’s own reports', async () => {
    // triage:read alone reads the user's organisations' reports: the API answers every report of
    // their own with a refusal, so a lookup under it could only refuse the comment outright. The
    // API checks whose report it is when the comment is posted.
    const { graphql } = api();
    harness = await connectTools({ graphql, grantedScopes: ['reports:write', 'triage:read'] });
    const result = await harness.call('add_report_comment', { reportId: 'r1', content: 'hi' });
    expect(result.isError).toBeFalsy();
    expect(graphql.calls.map((c) => c.operation)).not.toContain('GetReportRef');
  });

  it('refuses, asking for reports:read, when it could post on either side and holds only triage:read', async () => {
    const { graphql, approvals } = api();
    harness = await connectTools({
      graphql,
      grantedScopes: ['reports:write', 'triage:write', 'triage:read'],
    });
    const result = await harness.call('add_report_comment', { reportId: 'r1', content: 'hi' });
    expect(result.isError).toBe(true);
    expect(textOf(result)).toContain('Grant reports:read');
    expect(approvals.created).toEqual([]);
    expect(graphql.calls).toEqual([]);
  });

  it('resends a comment whose answer was lost after BugSecure posted it, with the same key: one comment', async () => {
    const write = idempotentWrite(() => ({ addReportComment: posted }), { drop: 1 });
    const { graphql, approvals } = api({ AddReportComment: write });
    harness = await connectTools({ graphql, grantedScopes: ['reports:write'] });

    const result = await harness.call('add_report_comment', { reportId: 'r1', content: 'Hello' });

    expect(result.isError).toBeFalsy();
    expect(result.structuredContent).toMatchObject({ comment: { id: 'c9' } });
    expect(harness.prompts).toHaveLength(1);
    const keys = withoutLookups(graphql.calls).map((c) => c.variables.clientRequestId);
    expect(keys).toEqual([approvals.created[0]?.clientRequestId, approvals.created[0]?.clientRequestId]);
    expect(keys[0]).toEqual(REQUEST_ID);
    expect(write.writes()).toBe(1);
  });

  it('says the comment may have been posted when the resend gets no answer either', async () => {
    const write = idempotentWrite(() => ({ addReportComment: posted }), { drop: 2 });
    const { graphql } = api({ AddReportComment: write });
    harness = await connectTools({ graphql, grantedScopes: ['reports:write'] });

    const result = await harness.call('add_report_comment', { reportId: 'r1', content: 'Hello' });

    expect(result.isError).toBe(true);
    const text = textOf(result);
    expect(text).toContain('may already have been made');
    expect(text).toContain('do not ask the user to approve it again');
    expect(text).toContain('get_report');
    expect(text).not.toContain('retry shortly');
    expect(withoutLookups(graphql.calls)).toHaveLength(2);
    expect(write.writes()).toBe(1);
  });

  it('relays an API that found no approval for the write, without retrying, and says to check first', async () => {
    const { graphql } = api({
      AddReportComment: () => {
        throw new BugSecureError(
          'APPROVAL_REQUIRED',
          'Nothing was sent: BugSecure found no approval matching this exact change.',
          {
            hint: 'Do not retry this call, and do not ask the user to approve it again yet: check first.',
          },
        );
      },
    });
    harness = await connectTools({ graphql, grantedScopes: ['reports:write'] });
    const result = await harness.call('add_report_comment', { reportId: 'r1', content: 'Hello' });
    expect(result.isError).toBe(true);
    expect(textOf(result)).toContain('found no approval matching this exact change');
    expect(textOf(result)).toContain('Do not retry');
    expect(withoutLookups(graphql.calls)).toHaveLength(1);
  });
});
