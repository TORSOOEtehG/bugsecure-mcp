/**
 * Whose report a report id refers to, looked up before a write: used to check
 * which side of the report the caller acts on. The review page on BugSecure
 * shows the user what the id refers to; nothing is looked up here for display.
 */
import { BugSecureError } from '../../errors.js';
import type { GetReportRefQuery } from '../../graphql/generated.js';
import type { Scope } from '../../scopes.js';
import type { ToolContext } from '../define-tool.js';
import { assertNotOwnReport, requireViewerWhenAmbiguous } from './report.js';

export type ReportRef = NonNullable<GetReportRefQuery['report']>;

/** The side of a report a write tool acts on: the reporter's, or the organisation's it was submitted to. */
export type ReportSide = 'researcher' | 'organization';

/**
 * What each side reads its reports with, and how a refusal speaks of them. The
 * API serves both sides through the same `report` field and answers with the
 * token's scopes: `reports:read` shows the caller's own reports and
 * `triage:read` their organisations', so a side's read scope is the only one
 * under which a lookup for that side can succeed, and the other side's read
 * scope is no help to it.
 */
const SIDES = {
  researcher: {
    readScope: 'reports:read',
    reads: 'your own reports',
    check: 'it is one of your own reports',
    findIt: 'list_my_reports',
  },
  organization: {
    readScope: 'triage:read',
    reads: 'your organisations’ reports',
    check: 'it was submitted to your organisation',
    findIt: 'list_org_reports',
  },
} as const satisfies Record<ReportSide, { readScope: Scope; reads: string; check: string; findIt: string }>;

export interface ReportLookup {
  /** The report, or undefined when this connection cannot read the side's reports (no lookup was made). */
  readonly report: ReportRef | undefined;
}

/**
 * Read the report a write is about, and refuse the write when that cannot be
 * done: a refusal by the API (session expired, a scope withheld, AI triage
 * access disabled, rate limit…) is passed on as it is, so the user is told
 * what to do about it; any other failure becomes UPSTREAM_ERROR; a report the
 * API answers `null` for is NOT_FOUND. The refusal speaks of the side the
 * caller acts on. Nothing is written blind.
 */
const readReportRef = async (
  context: Pick<ToolContext, 'signal'>,
  side: ReportSide,
  fetch: () => Promise<GetReportRefQuery>,
): Promise<ReportRef> => {
  const { check, findIt } = SIDES[side];
  let report: GetReportRefQuery['report'];
  try {
    ({ report } = await fetch());
  } catch (error) {
    if (context.signal.aborted || error instanceof BugSecureError) throw error;
    throw new BugSecureError(
      'UPSTREAM_ERROR',
      `Nothing was sent: the report could not be read to check ${check}.`,
      {
        hint: 'Try again shortly.',
        cause: error,
      },
    );
  }
  if (report === null) {
    throw new BugSecureError(
      'NOT_FOUND',
      `Nothing was sent: the report could not be read to check ${check}. It is not visible to your account.`,
      { hint: `Check the id with ${findIt}, then try again.` },
    );
  }
  return report;
};

/**
 * Look the report up before a comment is posted on it, if this connection
 * holds the read scope of the side the comment is posted on (`SIDES`): under
 * it, a lookup that cannot complete refuses the comment rather than letting
 * it be written blind (see `readReportRef`), so the user is not asked to
 * approve a comment the API would refuse, and the real reason is kept. Without
 * that scope the report stays unknown and no lookup is made, the other side's
 * read scope included: the API would refuse every report the comment could
 * legitimately be posted on, so looking would only refuse the tool outright.
 * The caller then decides what it can do without the report:
 * `requireSideKnown` refuses a token that could post on either side, and on a
 * single side the API checks whose report it is. `fetch` sends GetReportRef
 * from the calling tool's file.
 */
export const lookupReport = async (
  context: Pick<ToolContext, 'granted' | 'signal'>,
  side: ReportSide,
  fetch: () => Promise<GetReportRefQuery>,
): Promise<ReportLookup> => {
  if (!context.granted.has(SIDES[side].readScope)) return { report: undefined };
  const report = await readReportRef(context, side, fetch);
  return { report };
};

/**
 * A comment tool must know which side it posts on when the token could post
 * on either (both reports:write and triage:write): the API decides by whose
 * report it is, so posting "as the researcher" on an organisation's report
 * would land as an organisation comment, and vice versa. Only the read scope
 * of the tool's own side can tell (`lookupReport`), so that is the one asked for.
 */
export const requireSideKnown = (
  report: ReportRef | undefined,
  bothSides: boolean,
  side: ReportSide,
): void => {
  if (report === undefined && bothSides) {
    const { readScope, reads } = SIDES[side];
    throw new BugSecureError(
      'FORBIDDEN',
      'Nothing was sent: this connection can comment as a researcher and as an organisation, and the report could not be read to check which side this report is on.',
      {
        hint: `Grant ${readScope} (${reads}) so the report can be checked, or use the BugSecure website.`,
      },
    );
  }
};

/**
 * The report an organisation-side write changes (its status, its grade, who
 * triages it), read and checked before anything is asked or sent: submitted
 * to one of the caller's organisations, not filed by the caller. A report
 * that cannot be read is refused rather than written blind, because then
 * neither check can run; so is a caller who cannot be told from the reporter
 * (unknown user on a token that also reads their own reports). The API
 * refuses a member acting on their own report anyway; this keeps the client
 * from asking for, or sending, a write whose side it could not check.
 *
 * Unlike `lookupReport`, there is no scope under which the report may stay
 * unknown: these writes need it (`triage:read` is required), so the lookup
 * always runs and a lookup that cannot complete refuses the write (see
 * `readReportRef`).
 *
 * Called from the tool's payload, which runs before asking AND before sending.
 */
export const orgSideReport = async (
  context: Pick<ToolContext, 'granted' | 'signal' | 'viewerId'>,
  fetch: () => Promise<GetReportRefQuery>,
): Promise<ReportRef> => {
  requireViewerWhenAmbiguous(context.viewerId, context.granted.has('reports:read'));
  const report = await readReportRef(context, 'organization', fetch);
  assertNotOwnReport(report.reporter.id, context.viewerId);
  return report;
};
