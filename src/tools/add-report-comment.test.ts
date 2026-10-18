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

  it('passes the API’s own refusal of the lookup on, so the user is told what to do', async () => {
    // With a read scope the report is read before anything is asked. An
    // expired session (or a withheld scope, a rate limit) is the user's to act
    // on: it must reach them as it is, not as "try again".
    const { graphql, approvals } = api({
      GetReportRef: () => {
        throw new BugSecureError('SESSION_EXPIRED', 'Your session expired.', { hint: 'Run login again.' });
      },
    });
    harness = await connectTools({
      graphql,
      grantedScopes: ['reports:write', 'reports:read'],
      viewerId: 'researcher-1',
    });

    const result = await harness.call('add_report_comment', { reportId: 'r1', content: 'Test comment' });

    expect(result.isError).toBe(true);
    expect(textOf(result)).toContain('Your session expired.');
    expect(textOf(result)).toContain('Run login again.');
    expect(textOf(result)).not.toContain('Try again shortly');
    expect(approvals.created).toEqual([]);
    expect(withoutLookups(graphql.calls)).toEqual([]);
  });

  it('refuses, rather than posts blind, when the lookup fails for any other reason', async () => {
    const { graphql, approvals } = api({
      GetReportRef: () => {
        throw new Error('socket hang up');
      },
    });
    harness = await connectTools({
      graphql,
      grantedScopes: ['reports:write', 'reports:read'],
      viewerId: 'researcher-1',
    });

    const result = await harness.call('add_report_comment', { reportId: 'r1', content: 'Test comment' });

    expect(result.isError).toBe(true);
    expect(textOf(result)).toContain('could not be read to check which side it is on');
    expect(textOf(result)).toContain('Try again shortly');
    expect(approvals.created).toEqual([]);
    expect(withoutLookups(graphql.calls)).toEqual([]);
  });

  it('refuses a report the API answers null for, instead of asking the user to approve a doomed comment', async () => {
    const { graphql, approvals } = api({ GetReportRef: () => ({ report: null }) });
    harness = await connectTools({
      graphql,
      grantedScopes: ['reports:write', 'reports:read'],
      viewerId: 'researcher-1',
    });

    const result = await harness.call('add_report_comment', { reportId: 'r1', content: 'Test comment' });

    expect(result.isError).toBe(true);
    expect(textOf(result)).toContain('not visible to your account');
    expect(approvals.created).toEqual([]);
    expect(withoutLookups(graphql.calls)).toEqual([]);
  });

  it('sends nothing when the lookup succeeded before asking but fails before sending', async () => {
    // The payload is built twice: before the user is asked, and again once
    // they approved, so that what is sent is checked against the report as it
    // is NOW. A lookup that fails on the second pass refuses the send, even
    // though the approval exists; the comment was never written.
    let lookups = 0;
    const { graphql, approvals } = api({
      GetReportRef: () => {
        lookups += 1;
        if (lookups === 1) return { report: { id: 'r1', reporter: { id: 'researcher-1' } } };
        throw new BugSecureError('SESSION_EXPIRED', 'Your session expired.', { hint: 'Run login again.' });
      },
    });
    harness = await connectTools({
      graphql,
      grantedScopes: ['reports:write', 'reports:read'],
      viewerId: 'researcher-1',
    });

    const result = await harness.call('add_report_comment', { reportId: 'r1', content: 'Test comment' });

    expect(result.isError).toBe(true);
    expect(textOf(result)).toContain('Your session expired.');
    expect(lookups).toBe(2);
    // The user was asked, and approved: that is not enough to send blind.
    expect(approvals.created).toHaveLength(1);
    expect(harness.prompts).toHaveLength(1);
    expect(withoutLookups(graphql.calls)).toEqual([]);
  });

  it('refuses when it could post on either side and cannot read the report to tell which', async () => {
    const { graphql, approvals } = api();
    harness = await connectTools({ graphql, grantedScopes: ['reports:write', 'triage:write'] });
    const result = await harness.call('add_report_comment', { reportId: 'r1', content: 'hi' });
    expect(result.isError).toBe(true);
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
