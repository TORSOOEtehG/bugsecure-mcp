/**
 * Approval of write tools on the BugSecure website, through a URL-mode
 * elicitation (2026-07-28 multi round-trip requests), including the retries a
 * real client could tamper with, and the clients that cannot open URLs.
 */
import { randomBytes } from 'node:crypto';

import { type Client, InMemoryTransport } from '@modelcontextprotocol/client';
import { createMcpHandler, type McpHttpHandler, type ServerContext } from '@modelcontextprotocol/server';
import { afterEach, describe, expect, it, vi } from 'vitest';

import {
  type ApprovalMode,
  FAKE_WEB_URL,
  type FakeAgentApprovals,
  fakeAgentApprovals,
  fakeGraphQL,
  type FakeGraphQL,
  lookups,
  type OperationHandler,
} from '../../test/helpers/fake-graphql.js';
import { REPORTER_ID } from '../../test/helpers/report-fixtures.js';
import {
  APPROVED_OPERATION,
  ORG_SIDE_WRITE_TOOLS,
  REPORT_CHANGING_ORG_TOOLS,
  REPORT_READING_WRITE_TOOLS,
  SAMPLE_ARGS,
  WRITE_OPERATION,
} from '../../test/helpers/sample-args.js';
import {
  connectTools,
  elicitingClient,
  type ElicitationPrompt,
  type Harness,
  type OpenAnswer,
  TEST_GATE,
  testGate,
  textOf,
} from '../../test/helpers/tool-harness.js';
import { BugSecureError } from '../errors.js';
import { mapGraphQLErrors } from '../graphql/errors.js';
import { createLogger, silentLogger } from '../logger.js';
import { SCOPES } from '../scopes.js';
import { buildServer } from '../server.js';
import {
  ApprovalGate,
  APPROVAL_TTL_SECONDS,
  approvalMessage,
  argsDigest,
  AWAITING_MESSAGE,
  CONSUMED_MESSAGE,
  DECLINED_MESSAGE,
  EXPIRED_MESSAGE,
  FALLBACK_MESSAGE,
  NOT_OPENED_MESSAGE,
  payloadDigest,
  UNKNOWN_STATUS_MESSAGE,
  POLL_ANSWER_MARGIN_MS,
  MAX_WRITE_RESERVE_MS,
  MIN_WRITE_ATTEMPT_MS,
  pollBudgetFor,
  pollBudgetWithin,
  pollDeadline,
  writeAttempt,
  SETTINGS_PATH,
  supportsUrlElicitation,
} from './approval.js';
import { isWriteTool, mutation, type WritePayload } from './define-tool.js';
import { AddReportCommentDocument } from '../graphql/generated.js';
import { ALL_TOOLS } from './index.js';
import { CLIENT_REQUEST_ID, partRequestId } from './shared/request-id.js';

const posted = { id: 'c9', reportId: 'r1', isInternal: false, createdAt: '2026-09-21T10:00:00.000Z' };
const WRITES: Record<string, OperationHandler> = {
  AddReportComment: () => ({ addReportComment: posted }),
  AddTriageComment: () => ({ addReportComment: { ...posted, isInternal: true } }),
  SubmitReport: () => ({
    submitReport: {
      id: 'r1',
      title: 't',
      status: 'NEW',
      claimedSeverity: 'HIGH',
      claimedCvssScore: null,
      createdAt: posted.createdAt,
      program: null,
    },
  }),
  RaiseAppeal: () => ({
    raiseAppeal: {
      id: 'ap1',
      reportId: 'r1',
      adjudicationId: 'a1',
      status: 'OPEN',
      createdAt: posted.createdAt,
    },
  }),
  UpdateReportStatus: () => ({
    updateReportStatus: { id: 'r1', status: 'IN_TRIAGE', duplicateOfId: null, updatedAt: posted.createdAt },
  }),
  GradeReport: () => ({ adjudicateReport: null }),
  MarkNotificationRead: () => ({ markNotificationAsRead: true }),
  MarkAllNotificationsRead: () => ({ markAllNotificationsAsRead: true }),
  UpdateMyProfile: () => ({
    updateResearcherProfile: { bio: 'I hunt stored XSS.', website: '', country: 'KE' },
  }),
  SaveDisclosureDraft: () => ({ saveReportDisclosure: null }),
  AssignReport: () => ({
    assignTriageAnalyst: {
      id: 'r1',
      assignedTriage: { id: 'triager-1', username: 'tri' },
      updatedAt: posted.createdAt,
    },
  }),
};

/** The fake API: safety lookups, every write, and the approval state machine in `mode`. */
const api = (
  mode: ApprovalMode = 'approve',
  overrides: Record<string, OperationHandler> = {},
): { graphql: FakeGraphQL; approvals: FakeAgentApprovals } => {
  const approvals = fakeAgentApprovals(mode);
  return {
    graphql: fakeGraphQL({ ...lookups(), ...WRITES, ...approvals.handlers, ...overrides }),
    approvals,
  };
};

const WRITE_TOOLS = ALL_TOOLS.filter(isWriteTool).map((t) => t.name);
const viewerFor = (name: string): string => (ORG_SIDE_WRITE_TOOLS.has(name) ? 'triager-1' : REPORTER_ID);
const writesIn = (graphql: FakeGraphQL): string[] =>
  graphql.calls.map((c) => c.operation).filter((op) => Object.values(WRITE_OPERATION).includes(op));
const reviewUrlOf = (approvals: FakeAgentApprovals, index = 0): string =>
  `${FAKE_WEB_URL}/agent-approvals/${approvals.created[index]?.id ?? '(none)'}`;

let harness: Harness | undefined;
afterEach(async () => {
  await harness?.close();
  harness = undefined;
  vi.restoreAllMocks();
});

describe('every write tool', () => {
  it('is covered by this suite', () => {
    expect(WRITE_TOOLS.sort()).toEqual([
      'add_report_comment',
      'add_triage_comment',
      'assign_report',
      'grade_report',
      'mark_notifications_read',
      'raise_appeal',
      'save_disclosure_draft',
      'submit_report',
      'update_my_profile',
      'update_report_status',
    ]);
  });

  it.each(WRITE_TOOLS)(
    '%s registers its exact payload, sends the user to its review page, and writes only once approved',
    async (name) => {
      const { graphql, approvals } = api('approve');
      harness = await connectTools({ graphql, viewerId: viewerFor(name) });
      const args = SAMPLE_ARGS[name] ?? {};

      const result = await harness.call(name, args);

      expect(result.isError).toBeFalsy();
      // One approval, whose parts are the mutation(s) the tool then sent.
      expect(approvals.created).toHaveLength(1);
      const approval = approvals.created[0]!;
      expect(approval.parts.length).toBeGreaterThan(0);
      for (const part of approval.parts) expect(part.operation).toBe(APPROVED_OPERATION[name]);
      expect(approval.clientDigest).toMatch(/^[A-Za-z0-9_-]{43}$/);
      // One URL-mode elicitation, on the configured origin, naming no argument value.
      expect(harness.prompts).toHaveLength(1);
      const prompt = harness.prompts[0]!;
      expect(prompt.mode).toBe('url');
      expect(prompt.url).toBe(reviewUrlOf(approvals));
      expect(prompt.message).toMatch(
        /^bugsecure-mcp wants to .+ on BugSecure, as you\. Review and approve it on bugsecure\.test/,
      );
      expect(prompt.message).not.toMatch(/https?:/);
      for (const value of Object.values(args)) {
        if (typeof value === 'string' && value.length >= 3) expect(prompt.message).not.toContain(value);
      }
      // The write(s) went out, after the approval, with the arguments that were registered.
      const writes = graphql.calls.filter((c) => c.operation === WRITE_OPERATION[name]);
      expect(writes.length).toBe(approval.parts.length);
      for (const [index, write] of writes.entries()) {
        const { clientRequestId, ...variables } = write.variables;
        expect(variables).toEqual(approval.parts[index]?.arguments);
        expect(clientRequestId).toBe(
          approval.parts.length === 1
            ? approval.clientRequestId
            : partRequestId(approval.clientRequestId, index),
        );
      }
      const sequence = graphql.calls.map((c) => c.operation);
      expect(sequence.indexOf('CreateAgentApproval')).toBeLessThan(
        sequence.indexOf(WRITE_OPERATION[name] ?? ''),
      );
    },
  );

  it.each(WRITE_TOOLS)('%s creates a new approval, with a new key, once the first was used', async (name) => {
    const { graphql, approvals } = api('approve');
    harness = await connectTools({ graphql, viewerId: viewerFor(name) });
    await harness.call(name, SAMPLE_ARGS[name] ?? {});
    const first = approvals.created[0]!;
    // The API uses an approval up when the write it approved runs.
    approvals.decide(first.id, 'CONSUMED');

    await harness.call(name, SAMPLE_ARGS[name] ?? {});

    expect(approvals.created).toHaveLength(2);
    expect(approvals.created[1]?.clientRequestId).not.toBe(first.clientRequestId);
    const keys = graphql.calls
      .filter((c) => c.operation === WRITE_OPERATION[name])
      .map((c) => String(c.variables.clientRequestId));
    expect(new Set(keys).size).toBe(keys.length);
    for (const key of keys) expect(key).toMatch(CLIENT_REQUEST_ID);
  });

  // Report e6629484: a write that changes an organisation's report is never registered, asked for, or
  // sent, when the report could not be read to check it is not the caller's own. The same holds for a
  // comment whose report is read (the token holds the side's read scope, as 'all' does here).
  it.each([...REPORT_READING_WRITE_TOOLS])(
    '%s refuses, registering nothing, when the report cannot be read',
    async (name) => {
      const { graphql, approvals } = api('approve', {
        GetReportRef: () => {
          throw new Error('lookup down');
        },
      });
      harness = await connectTools({ graphql, viewerId: viewerFor(name) });
      const result = await harness.call(name, SAMPLE_ARGS[name] ?? {});
      expect(result.isError).toBe(true);
      expect(textOf(result)).toContain('Nothing was sent: the report could not be read');
      expect(harness.prompts).toHaveLength(0);
      expect(approvals.created).toEqual([]);
      expect(writesIn(graphql)).toEqual([]);
    },
  );

  it.each([...REPORT_READING_WRITE_TOOLS])(
    '%s refuses a report the API answers null for, instead of asking the user to approve a doomed write',
    async (name) => {
      const { graphql, approvals } = api('approve', { GetReportRef: () => ({ report: null }) });
      harness = await connectTools({ graphql, viewerId: viewerFor(name) });
      const result = await harness.call(name, SAMPLE_ARGS[name] ?? {});
      expect(result.isError).toBe(true);
      expect(textOf(result)).toContain('not visible to your account');
      expect(harness.prompts).toHaveLength(0);
      expect(approvals.created).toEqual([]);
      expect(writesIn(graphql)).toEqual([]);
    },
  );

  it.each([...REPORT_READING_WRITE_TOOLS])(
    '%s sends nothing when the report can no longer be read once approved (the payload runs on both rounds)',
    async (name) => {
      let reads = 0;
      const { graphql, approvals } = api('approve', {
        GetReportRef: (v) => {
          reads += 1;
          return reads === 1 ? lookups().GetReportRef?.(v) : { report: null };
        },
      });
      harness = await connectTools({ graphql, viewerId: viewerFor(name) });
      const result = await harness.call(name, SAMPLE_ARGS[name] ?? {});
      expect(harness.prompts).toHaveLength(1);
      expect(approvals.created).toHaveLength(1);
      expect(result.isError).toBe(true);
      expect(textOf(result)).toContain('Nothing was sent: the report could not be read');
      expect(writesIn(graphql)).toEqual([]);
    },
  );

  it.each([...REPORT_CHANGING_ORG_TOOLS])(
    '%s refuses, registering nothing, when the signed-in user is unknown and their own reports are readable',
    async (name) => {
      const { graphql, approvals } = api('approve');
      harness = await connectTools({ graphql, viewerId: null });
      const result = await harness.call(name, SAMPLE_ARGS[name] ?? {});
      expect(result.isError).toBe(true);
      // assign_report refuses earlier still: it cannot name the assignee.
      expect(textOf(result)).toMatch(/Cannot tell (who you are|which reports are your own)/);
      expect(harness.prompts).toHaveLength(0);
      expect(approvals.created).toEqual([]);
      expect(graphql.calls.map((c) => c.operation)).not.toContain('GetReportRef');
    },
  );

  it.each([...REPORT_READING_WRITE_TOOLS])(
    '%s passes on why the API refused to show the report',
    async (name) => {
      const { graphql, approvals } = api('approve', {
        GetReportRef: () => {
          throw new BugSecureError('SESSION_EXPIRED', 'Your session expired.', { hint: 'Run login again.' });
        },
      });
      harness = await connectTools({ graphql, viewerId: viewerFor(name) });
      const result = await harness.call(name, SAMPLE_ARGS[name] ?? {});
      expect(result.isError).toBe(true);
      // The user's to act on: it reaches them as it is, not as "try again shortly".
      expect(textOf(result)).toContain('Your session expired.');
      expect(textOf(result)).toContain('Run login again.');
      expect(textOf(result)).not.toContain('Try again shortly');
      expect(harness.prompts).toHaveLength(0);
      expect(approvals.created).toEqual([]);
      expect(writesIn(graphql)).toEqual([]);
    },
  );

  it.each(WRITE_TOOLS)('%s sends nothing when the user does not open the review page', async (name) => {
    for (const open of ['decline', 'cancel'] as const) {
      const { graphql, approvals } = api('approve');
      harness = await connectTools({ graphql, open, viewerId: viewerFor(name) });
      const result = await harness.call(name, SAMPLE_ARGS[name] ?? {});
      expect(result.isError).toBe(true);
      expect(textOf(result)).toBe(NOT_OPENED_MESSAGE);
      // The approval exists (the user may still decide it on BugSecure), but no poll and no write.
      expect(approvals.created).toHaveLength(1);
      expect(approvals.created[0]?.polls).toBe(0);
      expect(writesIn(graphql)).toEqual([]);
      await harness.close();
      harness = undefined;
    }
  });
});

describe('the decision on BugSecure', () => {
  const args = { reportId: 'r1', content: 'Here is the account.' };

  it('writes once the user approved, with the approval’s key', async () => {
    const { graphql, approvals } = api({ approveAfter: 2 });
    harness = await connectTools({ graphql, viewerId: REPORTER_ID });
    const result = await harness.call('add_report_comment', args);
    expect(result.isError).toBeFalsy();
    expect(approvals.created[0]?.polls).toBe(3);
    const [write] = graphql.calls.filter((c) => c.operation === 'AddReportComment');
    expect(write?.variables.clientRequestId).toBe(approvals.created[0]?.clientRequestId);
  });

  it('gives up waiting when the budget is spent, saying to retry only when the user approved, with no URL', async () => {
    const { graphql, approvals } = api('pending');
    harness = await connectTools({
      graphql,
      viewerId: REPORTER_ID,
      gate: { pollIntervalMs: 2, pollBudgetMs: 20 },
    });
    const result = await harness.call('add_report_comment', args);
    expect(result.isError).toBe(true);
    expect(textOf(result)).toBe(AWAITING_MESSAGE);
    expect(textOf(result)).not.toMatch(/https?:|agent-approvals/);
    expect(approvals.created[0]?.polls).toBeGreaterThan(1);
    expect(approvals.created[0]?.polls).toBeLessThanOrEqual(12);
    expect(writesIn(graphql)).toEqual([]);
  });

  it.each([
    ['decline', DECLINED_MESSAGE],
    ['expire', EXPIRED_MESSAGE],
    ['consumed', CONSUMED_MESSAGE],
  ] as const)('sends nothing when the approval is %s, and says what to do', async (mode, message) => {
    const { graphql } = api(mode);
    harness = await connectTools({ graphql, viewerId: REPORTER_ID });
    const result = await harness.call('add_report_comment', args);
    expect(result.isError).toBe(true);
    expect(textOf(result)).toBe(message);
    expect(writesIn(graphql)).toEqual([]);
  });

  it('a used approval sends the model to a read tool, not to a new approval', () => {
    expect(CONSUMED_MESSAGE).toContain('was sent then');
    expect(CONSUMED_MESSAGE).toContain('get_report or list_my_reports');
    expect(CONSUMED_MESSAGE).not.toContain('Nothing was sent');
  });

  it('treats an approval the API still reports live but past its expiry as expired', async () => {
    const { graphql, approvals } = api('approve');
    harness = await connectTools({ graphql, viewerId: REPORTER_ID });
    // A first round registers it; then let it lapse before the user "approves".
    const pending = fakeAgentApprovals('pending');
    const stale = fakeGraphQL({ ...lookups(), ...WRITES, ...pending.handlers });
    await harness.close();
    harness = await connectTools({
      graphql: stale,
      viewerId: REPORTER_ID,
      gate: { pollIntervalMs: 1, pollBudgetMs: 5 },
    });
    await harness.call('add_report_comment', args);
    const registered = pending.created[0]!;
    registered.expiresAt = new Date(Date.now() - 1_000).toISOString();
    pending.decide(registered.id, 'APPROVED');
    const result = await harness.call('add_report_comment', args);
    expect(result.isError).toBe(true);
    // The lapsed one is not reused: a new one is created (and shown), nothing written.
    expect(pending.created).toHaveLength(2);
    expect(writesIn(stale)).toEqual([]);
    expect(approvals.created).toEqual([]);
  });
});

describe('clients that cannot open the review page', () => {
  const args = { reportId: 'r1', content: 'Here is the account.' };

  it('get the approval created and the menu path, then a plain second call finds it approved and writes', async () => {
    const { graphql, approvals } = api('approve');
    harness = await connectTools({ graphql, open: 'none', viewerId: REPORTER_ID });

    const first = await harness.call('add_report_comment', args);
    expect(first.isError).toBe(true);
    expect(textOf(first)).toBe(FALLBACK_MESSAGE);
    expect(textOf(first)).toContain(SETTINGS_PATH);
    expect(textOf(first)).not.toMatch(/https?:|agent-approvals\//);
    expect(approvals.created).toHaveLength(1);
    expect(harness.prompts).toHaveLength(0);
    expect(writesIn(graphql)).toEqual([]);

    // The user approved it under Settings → Agent approvals meanwhile.
    const second = await harness.call('add_report_comment', args);
    expect(second.isError).toBeFalsy();
    expect(approvals.created).toHaveLength(1);
    const [write] = graphql.calls.filter((c) => c.operation === 'AddReportComment');
    expect(write?.variables.clientRequestId).toBe(approvals.created[0]?.clientRequestId);
  });

  it('do not get a second approval while the first is pending', async () => {
    const { graphql, approvals } = api('pending');
    harness = await connectTools({ graphql, open: 'none', viewerId: REPORTER_ID });
    for (let i = 0; i < 3; i += 1) {
      const result = await harness.call('add_report_comment', args);
      expect(textOf(result)).toBe(FALLBACK_MESSAGE);
    }
    expect(approvals.created).toHaveLength(1);
    expect(writesIn(graphql)).toEqual([]);
  });

  it.each([
    ['another origin', (id: string) => `https://evil.example/agent-approvals/${id}`],
    ['plain http', (id: string) => `http://bugsecure.test/agent-approvals/${id}`],
    ['a query string', (id: string) => `${FAKE_WEB_URL}/agent-approvals/${id}?next=x`],
    ['another approval’s page', () => `${FAKE_WEB_URL}/agent-approvals/${'x'.repeat(22)}`],
  ])('never show a review URL on %s: the menu path instead', async (_what, reviewUrl) => {
    const approvals = fakeAgentApprovals('approve', { reviewUrl });
    const graphql = fakeGraphQL({ ...lookups(), ...WRITES, ...approvals.handlers });
    harness = await connectTools({ graphql, viewerId: REPORTER_ID });
    const result = await harness.call('add_report_comment', args);
    expect(result.isError).toBe(true);
    expect(textOf(result)).toBe(FALLBACK_MESSAGE);
    expect(harness.prompts).toHaveLength(0);
    expect(approvals.created).toHaveLength(1);
    expect(writesIn(graphql)).toEqual([]);
  });

  it('get the menu path when no web origin is configured', async () => {
    const { graphql, approvals } = api('approve');
    harness = await connectTools({ graphql, webUrl: null, viewerId: REPORTER_ID });
    const result = await harness.call('add_report_comment', args);
    expect(textOf(result)).toBe(FALLBACK_MESSAGE);
    expect(harness.prompts).toHaveLength(0);
    expect(approvals.created).toHaveLength(1);
  });

  it('are told, with an older API, that it lacks agent approvals; nothing is created or sent', async () => {
    const graphql = fakeGraphQL({
      ...lookups(),
      ...WRITES,
      ListMyAgentApprovals: () => {
        throw mapGraphQLErrors([
          {
            message: 'Cannot query field "myAgentApprovals" on type "Query".',
            extensions: { code: 'GRAPHQL_VALIDATION_FAILED' },
          },
        ]);
      },
    });
    harness = await connectTools({ graphql, viewerId: REPORTER_ID });
    const result = await harness.call('add_report_comment', args);
    expect(result.isError).toBe(true);
    expect(textOf(result)).toContain('does not support agent approvals yet');
    expect(textOf(result)).toContain('October 2026');
    expect(textOf(result)).toContain('Nothing was written');
    expect(textOf(result)).not.toContain('Cannot query field');
    expect(writesIn(graphql)).toEqual([]);
  });
});

describe('client capability detection', () => {
  it.each([
    [undefined, false],
    [{}, false],
    [{ elicitation: {} }, false], // empty = form only (spec § Capabilities)
    [{ elicitation: { form: {} } }, false],
    [{ elicitation: { form: {}, url: {} } }, true],
    [{ elicitation: { url: {} } }, true],
  ])('%j → %s', (capabilities, expected) => {
    expect(supportsUrlElicitation(capabilities)).toBe(expected);
  });
});

describe('the digest and the message', () => {
  const part = mutation(AddReportCommentDocument, {
    input: { reportId: 'r1', content: 'a', isInternal: false },
  });

  it('bind the approval to the tool, the arguments and the exact payload', () => {
    const d = payloadDigest('add_report_comment', { reportId: 'r1', content: 'a' }, [part]);
    expect(d).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(payloadDigest('add_triage_comment', { reportId: 'r1', content: 'a' }, [part])).not.toBe(d);
    expect(payloadDigest('add_report_comment', { reportId: 'r1', content: 'b' }, [part])).not.toBe(d);
    const other = mutation(AddReportCommentDocument, {
      input: { reportId: 'r1', content: 'a', isInternal: true },
    });
    expect(payloadDigest('add_report_comment', { reportId: 'r1', content: 'a' }, [other])).not.toBe(d);
    // Key order does not matter; `undefined` members do not count (JSON drops them on the wire).
    expect(payloadDigest('add_report_comment', { content: 'a', reportId: 'r1', x: undefined }, [part])).toBe(
      d,
    );
  });

  it('caps the poll budget under a request deadline, keeping one write attempt and the answer', () => {
    expect(POLL_ANSWER_MARGIN_MS).toBe(2_000);
    // Defaults: a 60 s deadline and a 20 s write timeout leave 38 s to wait for the decision.
    expect(pollBudgetWithin(60_000, 45_000, 20_000)).toBe(38_000);
    // A short write timeout lets the configured budget stand.
    expect(pollBudgetWithin(60_000, 45_000, 5_000)).toBe(45_000);
    expect(pollBudgetWithin(30_000, 45_000, 20_000)).toBe(8_000);
    // BUGSECURE_REQUEST_TIMEOUT_MS=1000 gives the hosted adapter a 3 s deadline: the budget floors at a second.
    expect(pollBudgetWithin(3_000, 45_000, 1_000)).toBe(1_000);
    // An API timeout set for slow reads (up to 120 s) reserves at most 20 s: the user still gets 38 s to decide.
    expect(MAX_WRITE_RESERVE_MS).toBe(20_000);
    expect(pollBudgetWithin(60_000, 45_000, 120_000)).toBe(38_000);
    expect(pollBudgetFor(45_000, 120_000)).toBe(38_000);
  });

  it('gives a write attempt what is left of the call, never more than the API timeout, and skips a hopeless one', () => {
    const now = 1_000_000;
    expect(MIN_WRITE_ATTEMPT_MS).toBe(1_000);
    // Plenty of call left: the API timeout stands.
    expect(writeAttempt(now, now + 60_000, 20_000)).toBe(20_000);
    // 10 s of call left: a 20 s (or 120 s) timeout is cut to 8 s, so the attempt ends before the client gives up.
    expect(writeAttempt(now, now + 10_000, 20_000)).toBe(8_000);
    expect(writeAttempt(now, now + 10_000, 120_000)).toBe(8_000);
    // Under a second left for the attempt: not started, the next call sends it.
    expect(writeAttempt(now, now + 2_999, 20_000)).toBeNull();
    expect(writeAttempt(now, now + 3_000, 20_000)).toBe(1_000);
    // Tests shorten the margin and the minimum.
    expect(writeAttempt(now, now + 50, 30, 0, 1)).toBe(30);
    expect(writeAttempt(now, now + 20, 30, 0, 1)).toBe(20);
    expect(writeAttempt(now, now, 30, 0, 1)).toBeNull();
  });

  it('stops polling early enough in a call that already spent part of its deadline', () => {
    const now = 1_000_000;
    // Plenty of call left: the configured budget stands.
    expect(pollDeadline(now, 45_000, now + 120_000, 20_000)).toBe(now + 45_000);
    // The call arrived 30 s ago on a 60 s deadline: 30 s left, minus a 20 s write and the answer margin.
    expect(pollDeadline(now, 45_000, now + 30_000, 20_000)).toBe(now + 8_000);
    // Nothing left for a write: the deadline is already in the past, so the gate answers "awaiting" at once.
    expect(pollDeadline(now, 45_000, now + 10_000, 20_000)).toBeLessThan(now);
    // A long API timeout reserves 20 s at most, the write attempt itself being cut to what is left.
    expect(pollDeadline(now, 45_000, now + 30_000, 120_000)).toBe(now + 8_000);
    // Tests shorten the answer margin.
    expect(pollDeadline(now, 45_000, now + 30_000, 20_000, 0)).toBe(now + 10_000);
  });

  it('bounds the wait by the MCP client’s deadline too, whatever the server allows itself', () => {
    // stdio: only the client's 60 s; defaults give 38 s.
    expect(pollBudgetFor(45_000, 20_000)).toBe(38_000);
    // hosted with a 30 s API timeout: the adapter would allow 90 s, but the client gives up at 60 s,
    // so an approval must arrive by 38 s for the write (given the 20 s left at most) and the answer to be heard.
    expect(pollBudgetFor(45_000, 30_000, 90_000)).toBe(38_000);
    // hosted with a 10 s API timeout: the adapter allows 30 s, which leaves 18 s to wait.
    expect(pollBudgetFor(45_000, 10_000, 30_000)).toBe(18_000);
    // hosted with a short API timeout: the adapter's own 3 s deadline is the shorter one.
    expect(pollBudgetFor(45_000, 1_000, 3_000)).toBe(1_000);
  });

  it('names the action and the host, never a value or a URL', () => {
    const message = approvalMessage('comment on one of your reports', 'bugsecure.example');
    expect(message).toBe(
      'bugsecure-mcp wants to comment on one of your reports on BugSecure, as you. Review and approve it on ' +
        'bugsecure.example, the page this opens. Nothing is sent until you approve it there; the request ' +
        'expires in 15 minutes.',
    );
  });
});

/**
 * Raw 2026-07-28 wire, so a test can play a client that tampers with the
 * retry (the SDK client never would).
 */
describe('multi round-trip integrity (raw wire)', () => {
  interface Wire {
    readonly handler: McpHttpHandler;
    readonly graphql: FakeGraphQL;
    readonly approvals: FakeAgentApprovals;
    close(): Promise<void>;
  }

  const key = randomBytes(32);
  let wire: Wire | undefined;
  afterEach(async () => {
    await wire?.close();
    wire = undefined;
  });

  const serve = (
    principal = 'alice',
    mode: ApprovalMode = 'approve',
    shared?: FakeAgentApprovals,
    extra: Record<string, OperationHandler> = {},
  ): Wire => {
    const approvals = shared ?? fakeAgentApprovals(mode);
    const graphql = fakeGraphQL({ ...lookups(), ...WRITES, ...approvals.handlers, ...extra });
    const handler = createMcpHandler(() =>
      buildServer({
        mode: 'hosted',
        graphql,
        logger: silentLogger,
        grantedScopes: () => Promise.resolve(new Set(SCOPES)),
        viewerId: () => Promise.resolve(REPORTER_ID),
        readOnly: false,
        approvals: testGate({ key, principal }),
      }),
    );
    return { handler, graphql, approvals, close: () => handler.close() };
  };

  let id = 0;
  const callTool = async (
    handler: McpHttpHandler,
    args: Record<string, unknown>,
    retry: { inputResponses?: unknown; requestState?: string } = {},
    capabilities: Record<string, unknown> = { elicitation: { url: {} } },
    name = 'add_report_comment',
  ): Promise<Record<string, unknown>> => {
    id += 1;
    const response = await handler.fetch(
      new Request('http://wire.test/mcp', {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          accept: 'application/json, text/event-stream',
          'mcp-protocol-version': '2026-07-28',
          'mcp-method': 'tools/call',
          'mcp-name': name,
        },
        body: JSON.stringify({
          jsonrpc: '2.0',
          id,
          method: 'tools/call',
          params: {
            name,
            arguments: args,
            ...retry,
            _meta: {
              'io.modelcontextprotocol/protocolVersion': '2026-07-28',
              'io.modelcontextprotocol/clientCapabilities': capabilities,
              'io.modelcontextprotocol/clientInfo': { name: 'wire', version: '0' },
            },
          },
        }),
      }),
    );
    const body = (await response.json()) as { result?: Record<string, unknown>; error?: unknown };
    if (!body.result) throw new Error(`no result: ${JSON.stringify(body.error)}`);
    return body.result;
  };

  const opened = { approval: { action: 'accept' } };
  const args = { reportId: 'r1', content: 'Here is the account.' };

  const firstRound = async (
    w: Wire,
    a: Record<string, unknown> = args,
    name = 'add_report_comment',
  ): Promise<string> => {
    const result = await callTool(w.handler, a, {}, undefined, name);
    expect(result).toMatchObject({ resultType: 'input_required' });
    expect(result.inputRequests).toMatchObject({
      approval: {
        method: 'elicitation/create',
        params: { mode: 'url', url: reviewUrlOf(w.approvals, w.approvals.created.length - 1) },
      },
    });
    return result.requestState as string;
  };

  it('asks first, then writes exactly once on an approved retry, with the approval’s key', async () => {
    wire = serve();
    const requestState = await firstRound(wire);
    expect(writesIn(wire.graphql)).toHaveLength(0);

    const done = await callTool(wire.handler, args, { inputResponses: opened, requestState });
    expect(done).toMatchObject({ resultType: 'complete', structuredContent: { comment: { id: 'c9' } } });
    const [write] = wire.graphql.calls.filter((c) => c.operation === 'AddReportComment');
    expect(write?.variables.clientRequestId).toBe(wire.approvals.created[0]?.clientRequestId);
    // The state's payload is readable (only sealed): `v1.<base64url JSON {p: {t, d, i, c}, …}>.<mac>`.
    const payload = JSON.parse(
      Buffer.from(requestState.split('.')[1] ?? '', 'base64url').toString('utf8'),
    ) as {
      p: { t: string; a: string; d: string; i: string; c: string };
    };
    expect(payload.p).toEqual({
      t: 'add_report_comment',
      a: argsDigest('add_report_comment', args),
      d: wire.approvals.created[0]?.clientDigest,
      i: wire.approvals.created[0]?.id,
      c: wire.approvals.created[0]?.clientRequestId,
    });
  });

  it('a replayed approved retry finds the approval used, and sends the model to a read tool', async () => {
    wire = serve();
    const requestState = await firstRound(wire);
    await callTool(wire.handler, args, { inputResponses: opened, requestState });
    wire.approvals.decide(wire.approvals.created[0]!.id, 'CONSUMED');
    const again = await callTool(wire.handler, args, { inputResponses: opened, requestState });
    expect(again).toMatchObject({ isError: true });
    expect(JSON.stringify(again.content)).toContain('already used');
    expect(writesIn(wire.graphql)).toHaveLength(1);
  });

  it('answers a replay of a used approval as used before the tool’s own checks run, even once its write moved what they read', async () => {
    // save_disclosure_draft refuses a draft whose revision moved. Its own approved write bumps the
    // revision (3 → 4), so a replay of that very approval must be answered from the approval's
    // status, not refused by a check that would send the model to redo an edit that succeeded.
    let revision = 3;
    const draft = () => ({
      revision,
      title: 'Old public title',
      summary: 'Old summary.',
      writeup: 'Old write-up.',
      creditResearcher: false,
      severity: 'HIGH',
      certifiedReward: 500_000,
      researcherApproved: false,
      organizationApproved: true,
      publishedAt: null,
      isPublic: false,
    });
    wire = serve('alice', 'approve', undefined, {
      GetReportDisclosure: () => ({ reportDisclosureDraft: { side: 'researcher', draft: draft() } }),
      SaveDisclosureDraft: () => {
        revision = 4;
        return { saveReportDisclosure: { side: 'researcher', draft: draft() } };
      },
    });
    const disclosure = { ...(SAMPLE_ARGS.save_disclosure_draft ?? {}), reportId: 'r1', revision: 3 };
    const requestState = await firstRound(wire, disclosure, 'save_disclosure_draft');
    const done = await callTool(
      wire.handler,
      disclosure,
      { inputResponses: opened, requestState },
      undefined,
      'save_disclosure_draft',
    );
    expect(done).toMatchObject({ resultType: 'complete' });
    expect(revision).toBe(4);
    wire.approvals.decide(wire.approvals.created[0]!.id, 'CONSUMED');

    const reads = wire.graphql.calls.filter((c) => c.operation === 'GetReportDisclosure').length;
    const again = await callTool(
      wire.handler,
      disclosure,
      { inputResponses: opened, requestState },
      undefined,
      'save_disclosure_draft',
    );
    expect(again).toMatchObject({ isError: true });
    expect(JSON.stringify(again.content)).toContain('already used');
    expect(JSON.stringify(again.content)).not.toContain('now at revision');
    // The payload (and its revision check) was never built for the replay.
    expect(wire.graphql.calls.filter((c) => c.operation === 'GetReportDisclosure')).toHaveLength(reads);
    expect(wire.graphql.calls.filter((c) => c.operation === 'SaveDisclosureDraft')).toHaveLength(1);
  });

  it('starts over, creating a new approval and writing nothing, when the retry carries other arguments', async () => {
    wire = serve();
    const requestState = await firstRound(wire);
    const swapped = await callTool(
      wire.handler,
      { ...args, content: 'Something the user never saw.' },
      { inputResponses: opened, requestState },
    );
    expect(swapped).toMatchObject({ resultType: 'input_required' });
    expect(wire.approvals.created).toHaveLength(2);
    expect(wire.approvals.created[1]?.parts[0]?.arguments).toMatchObject({
      input: { content: 'Something the user never saw.' },
    });
    expect(JSON.stringify(swapped.inputRequests)).not.toContain('Something the user never saw.');
    expect(writesIn(wire.graphql)).toHaveLength(0);
  });

  it('starts over when the state was tampered with, forged, or minted for another principal, reusing the pending approval', async () => {
    wire = serve('alice', 'pending');
    const requestState = await firstRound(wire);
    const [version, body, mac] = requestState.split('.');
    const tampered = `${version ?? ''}.${body ?? ''}x.${mac ?? ''}`;
    for (const state of [tampered, 'v1.e30.AAAA', 'not-a-state']) {
      const result = await callTool(wire.handler, args, { inputResponses: opened, requestState: state });
      expect(result).toMatchObject({ resultType: 'input_required' });
    }
    // The same pending approval is shown again: no duplicate.
    expect(wire.approvals.created).toHaveLength(1);
    expect(wire.approvals.created[0]?.polls).toBe(0);

    const bob = serve('bob', 'pending', wire.approvals);
    try {
      const stolen = await callTool(bob.handler, args, { inputResponses: opened, requestState });
      expect(stolen).toMatchObject({ resultType: 'input_required' });
      expect(writesIn(bob.graphql)).toHaveLength(0);
    } finally {
      await bob.close();
    }
    expect(writesIn(wire.graphql)).toHaveLength(0);
  });

  it('writes nothing on an "approval" without state (fabricated by the client)', async () => {
    wire = serve('alice', 'pending');
    const result = await callTool(wire.handler, args, { inputResponses: opened });
    expect(result).toMatchObject({ resultType: 'input_required' });
    expect(writesIn(wire.graphql)).toHaveLength(0);
  });

  it('starts over once the state has expired', async () => {
    let now = Date.parse('2026-10-05T10:00:00Z');
    vi.spyOn(Date, 'now').mockImplementation(() => now);
    wire = serve('alice', 'pending');
    const requestState = await firstRound(wire);
    now += (APPROVAL_TTL_SECONDS + 1) * 1000;
    const late = await callTool(wire.handler, args, { inputResponses: opened, requestState });
    // The pending approval has lapsed too (same window): a new one is created.
    expect(late).toMatchObject({ resultType: 'input_required' });
    expect(wire.approvals.created).toHaveLength(2);
    expect(writesIn(wire.graphql)).toHaveLength(0);
  });

  it('never sends a URL elicitation to a client that did not declare the capability: the menu path instead', async () => {
    wire = serve('alice', 'pending');
    for (const capabilities of [{}, { elicitation: {} }, { elicitation: { form: {} } }]) {
      const result = await callTool(wire.handler, args, {}, capabilities);
      expect(result).toMatchObject({ isError: true });
      expect(result).not.toHaveProperty('inputRequests');
      expect(JSON.stringify(result.content)).toContain(SETTINGS_PATH);
    }
    expect(wire.approvals.created).toHaveLength(1);
  });

  it('logs ids and statuses only: never the arguments, the message or the URL', async () => {
    const lines: string[] = [];
    const logger = createLogger({ level: 'debug', write: (line) => lines.push(line) });
    const approvals = fakeAgentApprovals('approve');
    const graphql = fakeGraphQL({ ...lookups(), ...WRITES, ...approvals.handlers });
    const handler = createMcpHandler(() =>
      buildServer({
        mode: 'hosted',
        graphql,
        logger,
        grantedScopes: () => Promise.resolve(new Set(SCOPES)),
        viewerId: () => Promise.resolve(REPORTER_ID),
        readOnly: false,
        approvals: new ApprovalGate({ key, principal: 'alice', logger, ...TEST_GATE }),
      }),
    );
    wire = { handler, graphql, approvals, close: () => handler.close() };
    const requestState = await firstRound(wire);
    await callTool(wire.handler, args, { inputResponses: opened, requestState });
    const log = lines.join('\n');
    expect(log).toContain(approvals.created[0]?.id ?? '(none)');
    expect(log).toContain('APPROVED');
    expect(log).not.toContain('Here is the account');
    expect(log).not.toContain('agent-approvals');
    expect(log).not.toContain('bugsecure.test');
    expect(log).not.toContain('wants to');
  });
});

describe('aborting while waiting', () => {
  it('stops polling and rethrows the abort, sending nothing', async () => {
    const approvals = fakeAgentApprovals('pending');
    const graphql = fakeGraphQL({ ...lookups(), ...WRITES, ...approvals.handlers });
    const gate = testGate({ pollIntervalMs: 1_000, pollBudgetMs: 10_000 });
    const payload: WritePayload = {
      action: 'comment on one of your reports',
      parts: [
        mutation(AddReportCommentDocument, { input: { reportId: 'r1', content: 'a', isInternal: false } }),
      ],
    };
    const ctx = (state?: string): ServerContext =>
      ({
        mcpReq: {
          requestState: () => state,
          inputResponses: state === undefined ? undefined : { approval: { action: 'accept' } },
        },
      }) as never;
    const call = (signal: AbortSignal, state?: string) => ({
      toolName: 'add_report_comment',
      args: { reportId: 'r1', content: 'a' },
      ctx: ctx(state),
      clientCapabilities: { elicitation: { url: {} } },
      graphql,
      signal,
      deadlineAt: Date.now() + 60_000,
    });

    const first = await gate.check(call(new AbortController().signal), () => Promise.resolve(payload));
    expect(first.kind).toBe('respond');
    const requestState = (first as { result: { requestState?: string } }).result.requestState;
    expect(requestState).toBeTypeOf('string');

    const controller = new AbortController();
    const waiting = gate.check(call(controller.signal, requestState), () => Promise.resolve(payload));
    setTimeout(() => {
      controller.abort(new Error('client went away'));
    }, 10);
    await expect(waiting).rejects.toThrow('client went away');
    expect(approvals.created[0]?.polls).toBe(1);
    expect(writesIn(graphql)).toEqual([]);
  });
});

describe('2025-era clients', () => {
  it('over stateless HTTP cannot be asked, so they get the approval created and the menu path', async () => {
    const { graphql, approvals } = api('pending');
    harness = await connectTools({ graphql, era: 'legacy', viewerId: REPORTER_ID });
    const result = await harness.call('add_report_comment', { reportId: 'r1', content: 'hi' });
    expect(result.isError).toBe(true);
    expect(textOf(result)).toBe(FALLBACK_MESSAGE);
    expect(approvals.created).toHaveLength(1);
    expect(writesIn(graphql)).toHaveLength(0);
  });

  it.each(['accept', 'decline'] as const satisfies readonly OpenAnswer[])(
    'on a session transport (stdio) are sent to the review page with a real elicitation/create request: %s',
    async (open) => {
      const { graphql, approvals } = api('approve');
      const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
      const server = buildServer({
        mode: 'local',
        graphql,
        logger: silentLogger,
        grantedScopes: () => Promise.resolve(new Set(SCOPES)),
        viewerId: () => Promise.resolve(REPORTER_ID),
        readOnly: false,
        approvals: testGate(),
      });
      const prompts: ElicitationPrompt[] = [];
      const client: Client = elicitingClient(open, prompts);
      await server.connect(serverTransport);
      await client.connect(clientTransport);
      try {
        expect(client.getProtocolEra()).toBe('legacy');
        const result = await client.callTool({
          name: 'add_report_comment',
          arguments: { reportId: 'r1', content: 'hi' },
        });
        expect(prompts).toHaveLength(1);
        expect(prompts[0]?.mode).toBe('url');
        expect(prompts[0]?.url).toBe(reviewUrlOf(approvals));
        expect(result.isError ?? false).toBe(open === 'decline');
        expect(writesIn(graphql)).toHaveLength(open === 'accept' ? 1 : 0);
      } finally {
        await client.close();
        await server.close();
      }
    },
  );

  it('keep the call’s original deadline when the shim re-enters the handler after the user decided', async () => {
    // The shim answers the elicitation inside ONE client request: the client's clock has run since the
    // first entry. Here the user takes 130 ms of a 150 ms call, leaving less than the 30 ms write needs,
    // so the second entry must not poll and write as if it had a fresh 150 ms: it says "awaiting".
    const { graphql, approvals } = api('approve');
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    const server = buildServer({
      mode: 'local',
      graphql,
      logger: silentLogger,
      grantedScopes: () => Promise.resolve(new Set(SCOPES)),
      viewerId: () => Promise.resolve(REPORTER_ID),
      readOnly: false,
      approvals: testGate({ pollIntervalMs: 0, pollBudgetMs: 50, writeTimeoutMs: 30, answerMarginMs: 0 }),
      clientDeadlineMs: 150,
      writeTimeoutMs: 30,
      answerMarginMs: 0,
      minWriteAttemptMs: 1,
    });
    const prompts: ElicitationPrompt[] = [];
    const client: Client = elicitingClient('accept', prompts, {}, 130);
    await server.connect(serverTransport);
    await client.connect(clientTransport);
    try {
      expect(client.getProtocolEra()).toBe('legacy');
      const result = await client.callTool({
        name: 'add_report_comment',
        arguments: { reportId: 'r1', content: 'hi' },
      });
      expect(prompts).toHaveLength(1);
      expect(result.isError).toBe(true);
      expect(textOf(result)).toBe(AWAITING_MESSAGE);
      expect(approvals.created).toHaveLength(1);
      expect(writesIn(graphql)).toHaveLength(0);
    } finally {
      await client.close();
      await server.close();
    }
  });
});

describe('a decision state this version does not know', () => {
  let harness: Harness | undefined;
  afterEach(async () => {
    await harness?.close();
    harness = undefined;
  });

  it('sends nothing and says so, rather than failing generically', async () => {
    const approvals = fakeAgentApprovals('approve');
    const revoked: OperationHandler = (vars) => {
      const answer = approvals.handlers.GetAgentApproval?.(vars) as {
        agentApproval: Record<string, unknown>;
      };
      return { agentApproval: { ...answer.agentApproval, status: 'REVOKED' } };
    };
    const graphql = fakeGraphQL({
      ...lookups(),
      ...WRITES,
      ...approvals.handlers,
      GetAgentApproval: revoked,
    });
    harness = await connectTools({ graphql, grantedScopes: ['reports:write'] });
    const result = await harness.call('add_report_comment', { reportId: 'r1', content: 'hi' });
    expect(result.isError).toBe(true);
    expect(textOf(result)).toBe(UNKNOWN_STATUS_MESSAGE);
    expect(writesIn(graphql)).toEqual([]);
  });
});

describe('a decision that arrives after the poll budget', () => {
  let harness: Harness | undefined;
  afterEach(async () => {
    await harness?.close();
    harness = undefined;
  });

  it('is not acted on: the client has given up on the call, so nothing is sent and it is told to call again', async () => {
    const approvals = fakeAgentApprovals('approve');
    const slow: OperationHandler = async (vars) => {
      await new Promise((resolve) => setTimeout(resolve, 40));
      return approvals.handlers.GetAgentApproval?.(vars);
    };
    const graphql = fakeGraphQL({ ...lookups(), ...WRITES, ...approvals.handlers, GetAgentApproval: slow });
    harness = await connectTools({
      graphql,
      grantedScopes: ['reports:write'],
      gate: { pollIntervalMs: 1, pollBudgetMs: 5 },
    });
    const result = await harness.call('add_report_comment', { reportId: 'r1', content: 'late' });
    expect(result.isError).toBe(true);
    expect(textOf(result)).toBe(AWAITING_MESSAGE);
    // Approved on BugSecure (the slow read was given up on, not stopped), but the write never ran here.
    await new Promise((resolve) => setTimeout(resolve, 60));
    expect(approvals.created[0]?.status).toBe('APPROVED');
    expect(writesIn(graphql)).toEqual([]);
  });
});
