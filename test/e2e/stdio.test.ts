/**
 * End to end over the BUILT binary (dist/cli.js), spawned exactly as an MCP
 * client spawns it, over stdio, against a fake BugSecure API on loopback:
 *
 * - stdout carries only protocol traffic (the SDK client would choke otherwise);
 * - a signed-out server still starts, lists tools and explains how to sign in;
 * - protocol 2026-07-28: a write tool registers the write with the API, sends
 *   the user to its review page (URL-mode elicitation on the configured web
 *   origin) and writes only once the API says the user approved (declined,
 *   pending → nothing sent; a client without the capability → the menu path);
 * - a 2025-era client gets the same URL elicitation as a real elicitation/create.
 *
 * `pnpm run check` and CI build before testing. Without a build the suite is
 * skipped with a notice (run `pnpm build` first), so a cold `pnpm test` does
 * not fail on it — except in CI (`CI` set), where a missing build FAILS it:
 * there it must never be skipped silently.
 */
import { chmodSync, existsSync, mkdtempSync, writeFileSync } from 'node:fs';
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import type { Client } from '@modelcontextprotocol/client';
import { StdioClientTransport } from '@modelcontextprotocol/client/stdio';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { type ApprovalMode, type FakeAgentApprovals, fakeAgentApprovals } from '../helpers/fake-graphql.js';
import { type ElicitationPrompt, elicitingClient, type OpenAnswer } from '../helpers/tool-harness.js';

const CLI = join(import.meta.dirname, '..', '..', 'dist', 'cli.js');
const TOKEN = 'e2e-access-token';

const BUILT = existsSync(CLI);
if (!BUILT && process.env.CI === undefined) {
  process.stderr.write(
    `\nSkipping the end-to-end suite: ${CLI} does not exist. Run \`pnpm build\` first.\n\n`,
  );
}

interface ApiCall {
  readonly operation: string;
  readonly authorization: string | undefined;
  readonly variables: Record<string, unknown> | undefined;
}

let api: Server | undefined;
let apiUrl: string;
const apiCalls: ApiCall[] = [];
/** The approval state machine the fake API serves; replaced per test. */
let approvals: FakeAgentApprovals = fakeAgentApprovals('approve');
/** Review URLs on the fake API's own loopback origin, which the server is told is the web app (`--web-url`). */
const approvalsDecided = (mode: ApprovalMode): FakeAgentApprovals =>
  fakeAgentApprovals(mode, { reviewUrl: (id) => `${apiUrl}/agent-approvals/${id}` });

/**
 * A fake BugSecure API: answers the operations these tests use, records every
 * call. Its review URLs are on its own loopback origin, which the server is
 * configured to accept as the web app (`--web-url`).
 */
const fakeApi = (): Server => {
  return createServer((req, res) => {
    let raw = '';
    req.setEncoding('utf8');
    req.on('data', (chunk: string) => (raw += chunk));
    req.on('end', () => {
      const body = JSON.parse(raw) as { query: string; variables?: Record<string, unknown> };
      const operation = /\b(?:query|mutation)\s+(\w+)/.exec(body.query)?.[1] ?? '?';
      apiCalls.push({ operation, authorization: req.headers.authorization, variables: body.variables });
      // Own properties only: the name comes from the request, and a prototype key must not dispatch.
      const handler = Object.hasOwn(approvals.handlers, operation)
        ? approvals.handlers[operation]
        : undefined;
      const data =
        operation === 'AddReportComment'
          ? {
              addReportComment: {
                id: 'c1',
                reportId: 'r1',
                isInternal: false,
                createdAt: '2026-09-21T10:00:00.000Z',
              },
            }
          : operation === 'SearchPrograms'
            ? { programs: [] }
            : handler !== undefined
              ? handler(body.variables ?? {})
              : operation === 'GetReportRef'
                ? // The report a comment is about, read before the comment is posted; a
                  // scenario that needs the lookup to fail or to name another reporter
                  // registers its own handler, which wins.
                  { report: { id: body.variables?.id, reporter: { id: 'researcher-1' } } }
                : null;
      res.writeHead(data ? 200 : 400, { 'content-type': 'application/json' });
      res.end(JSON.stringify(data ? { data } : { errors: [{ message: `unexpected ${operation}` }] }));
    });
  });
};

/** A config dir holding a valid stored login for the fake API (file store, 0600). */
const signedInConfigDir = (scope: string): string => {
  const dir = mkdtempSync(join(tmpdir(), 'bsmcp-e2e-'));
  const now = Math.floor(Date.now() / 1000);
  const credentials = {
    version: 1,
    issuer: apiUrl,
    clientId: 'bugsecure-mcp-cli',
    resource: apiUrl,
    tokenEndpoint: `${apiUrl}/oauth/token`,
    accessToken: TOKEN,
    accessTokenExpiresAt: now + 3_600,
    scope,
    obtainedAt: now,
  };
  const file = join(dir, 'credentials.json');
  writeFileSync(file, JSON.stringify({ version: 1, entries: { [apiUrl]: credentials } }), { mode: 0o600 });
  chmodSync(file, 0o600);
  return dir;
};

const spawnClient = async (
  configDir: string,
  options: {
    open?: OpenAnswer;
    era?: 'modern' | 'legacy';
    prompts?: ElicitationPrompt[];
    webUrl?: boolean;
  } = {},
): Promise<Client> => {
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [CLI, '--api-url', apiUrl, ...(options.webUrl === false ? [] : ['--web-url', apiUrl])],
    env: {
      PATH: process.env.PATH ?? '',
      BUGSECURE_CREDENTIAL_STORE: 'file',
      BUGSECURE_CONFIG_DIR: configDir,
      BUGSECURE_LOG_LEVEL: 'silent',
      // Fast polling, so a pending approval gives up within the test's patience.
      BUGSECURE_APPROVAL_POLL_INTERVAL_MS: '100',
      BUGSECURE_APPROVAL_POLL_BUDGET_MS: '1000',
    },
    stderr: 'pipe',
  });
  const client = elicitingClient(
    options.open ?? 'accept',
    options.prompts ?? [],
    options.era === 'legacy' ? {} : { versionNegotiation: { mode: 'auto' } },
  );
  await client.connect(transport);
  return client;
};

beforeAll(async () => {
  if (!BUILT) {
    if (process.env.CI !== undefined)
      throw new Error(`${CLI} does not exist: run \`pnpm build\` before the end-to-end tests.`);
    return;
  }
  const server = fakeApi();
  api = server;
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  apiUrl = `http://127.0.0.1:${String((server.address() as AddressInfo).port)}`;
});

afterAll(async () => {
  // Nothing to close when setup failed or the suite was skipped.
  const server = api;
  if (server === undefined) return;
  await new Promise<void>((resolve) => {
    server.close(() => {
      resolve();
    });
  });
});

describe.skipIf(!BUILT && process.env.CI === undefined)('bugsecure-mcp over stdio (built binary)', () => {
  it('serves a signed-out session on the 2026-07-28 protocol, explaining how to sign in', async () => {
    const client = await spawnClient(mkdtempSync(join(tmpdir(), 'bsmcp-e2e-')));
    try {
      expect(client.getProtocolEra()).toBe('modern');
      expect(client.getServerVersion()?.name).toBe('bugsecure-mcp');
      expect(client.getServerCapabilities()?.tools).toEqual({ listChanged: false });
      const names = (await client.listTools()).tools.map((t) => t.name);
      expect(names).toEqual(expect.arrayContaining(['get_program', 'search_programs', 'submit_report']));

      const result = await client.callTool({ name: 'search_programs', arguments: {} });
      expect(result.isError).toBe(true);
      expect(JSON.stringify(result.content)).toContain('login');
    } finally {
      await client.close();
    }
  });

  it('calls the API with the stored token and returns structured output', async () => {
    const client = await spawnClient(signedInConfigDir('programs:read'));
    apiCalls.length = 0;
    try {
      const result = await client.callTool({ name: 'search_programs', arguments: {} });
      expect(result.isError).toBeFalsy();
      expect(result.structuredContent).toMatchObject({ programs: [], nextOffset: null });
      expect(apiCalls.map(({ operation, authorization }) => ({ operation, authorization }))).toEqual([
        { operation: 'SearchPrograms', authorization: `Bearer ${TOKEN}` },
      ]);
    } finally {
      await client.close();
    }
  });

  const matrix: readonly [era: 'modern' | 'legacy', decision: ApprovalMode | 'no-url', writes: number][] = [
    ['modern', 'approve', 1],
    ['modern', 'decline', 0],
    ['modern', 'pending', 0],
    ['modern', 'no-url', 0],
    ['legacy', 'approve', 1],
    ['legacy', 'decline', 0],
    ['legacy', 'pending', 0],
    ['legacy', 'no-url', 0],
  ];
  it.each(matrix)('%s client, the user %s on BugSecure → %i write(s)', async (era, decision, writes) => {
    approvals = approvalsDecided(decision === 'no-url' ? 'pending' : decision);
    const prompts: ElicitationPrompt[] = [];
    const client = await spawnClient(signedInConfigDir('reports:read reports:write'), {
      open: decision === 'no-url' ? 'none' : 'accept',
      era,
      prompts,
    });
    apiCalls.length = 0;
    try {
      expect(client.getProtocolEra()).toBe(era);
      const result = await client.callTool({
        name: 'add_report_comment',
        arguments: { reportId: 'r1', content: 'Here is the test account: e2e@example.test' },
      });

      // The write was registered for review, with the exact arguments, before anything else.
      expect(approvals.created).toHaveLength(1);
      expect(approvals.created[0]?.parts).toEqual([
        {
          operation: 'addReportComment',
          arguments: {
            input: {
              reportId: 'r1',
              content: 'Here is the test account: e2e@example.test',
              isInternal: false,
            },
          },
        },
      ]);
      const sent = apiCalls.filter((c) => c.operation === 'AddReportComment');
      expect(sent).toHaveLength(writes);
      // The write carries its approval's idempotency key.
      for (const call of sent)
        expect(call.variables?.clientRequestId).toBe(approvals.created[0]?.clientRequestId);
      if (decision === 'no-url') {
        expect(prompts).toHaveLength(0);
        expect(JSON.stringify(result.content)).toContain('Settings → Agent approvals');
        expect(JSON.stringify(result.content)).not.toContain('agent-approvals/');
      } else {
        expect(prompts).toHaveLength(1);
        expect(prompts[0]?.mode).toBe('url');
        expect(prompts[0]?.url).toBe(`${apiUrl}/agent-approvals/${approvals.created[0]?.id ?? ''}`);
        expect(prompts[0]?.message).not.toContain('e2e@example.test');
      }
      if (writes === 1) {
        expect(result.isError).toBeFalsy();
        expect(result.structuredContent).toMatchObject({ comment: { id: 'c1', reportId: 'r1' } });
      } else {
        expect(result.isError).toBe(true);
        expect(JSON.stringify(result.content)).toContain('Nothing was sent');
        if (decision === 'pending') expect(JSON.stringify(result.content)).toContain('awaiting the user');
      }
    } finally {
      await client.close();
    }
  });

  it('without a configured web app, sends the user to the menu instead of a URL', async () => {
    approvals = approvalsDecided('pending');
    const prompts: ElicitationPrompt[] = [];
    const client = await spawnClient(signedInConfigDir('reports:write'), { prompts, webUrl: false });
    try {
      const result = await client.callTool({
        name: 'add_report_comment',
        arguments: { reportId: 'r1', content: 'hi' },
      });
      expect(result.isError).toBe(true);
      expect(prompts).toHaveLength(0);
      expect(JSON.stringify(result.content)).toContain('Settings → Agent approvals');
      expect(approvals.created).toHaveLength(1);
    } finally {
      await client.close();
    }
  });

  it('refuses a tool whose scope the stored login lacks, with the exact login command', async () => {
    const client = await spawnClient(signedInConfigDir('programs:read'));
    apiCalls.length = 0;
    try {
      const result = await client.callTool({
        name: 'add_report_comment',
        arguments: { reportId: 'r1', content: 'hi' },
      });
      expect(result.isError).toBe(true);
      expect(JSON.stringify(result.content)).toContain(
        String.raw`login --scopes \"programs:read reports:write\"`,
      );
      expect(apiCalls).toHaveLength(0);
    } finally {
      await client.close();
    }
  });
});
