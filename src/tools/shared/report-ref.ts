/**
 * Whose report a report id refers to, looked up before a write: used to check
 * which side of the report the caller acts on. The review page on BugSecure
 * shows the user what the id refers to; nothing is looked up here for display.
 */
import { BugSecureError } from '../../errors.js';
import type { GetReportRefQuery } from '../../graphql/generated.js';
import type { ToolContext } from '../define-tool.js';
import { assertNotOwnReport, requireViewerWhenAmbiguous } from './report.js';

export type ReportRef = NonNullable<GetReportRefQuery['report']>;

export interface ReportLookup {
  /** The report, or undefined when it could not be looked up (not readable, not visible, or failed). */
  readonly report: ReportRef | undefined;
}

/**
 * Look the report up if this connection can read it (reports:read or
 * triage:read). Never throws for a failed lookup: the caller then decides
 * whether it can proceed without knowing whose report it is. `fetch` sends
 * GetReportRef from the calling tool's file.
 */
export const lookupReport = async (
  context: Pick<ToolContext, 'granted' | 'signal'>,
  fetch: () => Promise<GetReportRefQuery>,
  options: { failOnError?: boolean } = {},
): Promise<ReportLookup> => {
  if (!context.granted.has('reports:read') && !context.granted.has('triage:read'))
    return { report: undefined };
  try {
    const { report } = await fetch();
    return { report: report ?? undefined };
  } catch (error) {
    if (context.signal.aborted) throw error;

    if (options.failOnError) {
      throw new BugSecureError(
        'UPSTREAM_ERROR',
        'Nothing was sent: the report could not be read to check which side it is on.',
        { hint: 'Try again shortly.', cause: error },
      );
    }

    return { report: undefined };
  }
};

/**
 * A comment tool must know which side it posts on when the token could post
 * on either (both reports:write and triage:write): the API decides by whose
 * report it is, so posting "as the researcher" on an organisation's report
 * would land as an organisation comment, and vice versa.
 */
export const requireSideKnown = (report: ReportRef | undefined, bothSides: boolean, what: string): void => {
  if (report === undefined && bothSides) {
    throw new BugSecureError(
      'FORBIDDEN',
      `Nothing was sent: this connection can comment as a researcher and as an organisation, and the report could not be read to check which side ${what} is on.`,
      {
        hint: 'Grant reports:read (your own reports) or triage:read (your organisations’ reports) so the report can be checked, or use the BugSecure website.',
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
 * Unlike `lookupReport`, a refusal by the API (session expired, AI triage
 * access disabled, rate limit…) is passed on as it is, so the user is told
 * what to do about it.
 *
 * Called from the tool's payload, which runs before asking AND before sending.
 */
export const orgSideReport = async (
  context: Pick<ToolContext, 'granted' | 'signal' | 'viewerId'>,
  fetch: () => Promise<GetReportRefQuery>,
): Promise<ReportRef> => {
  requireViewerWhenAmbiguous(context.viewerId, context.granted.has('reports:read'));
  let report: GetReportRefQuery['report'];
  try {
    ({ report } = await fetch());
  } catch (error) {
    if (context.signal.aborted || error instanceof BugSecureError) throw error;
    throw new BugSecureError(
      'UPSTREAM_ERROR',
      'Nothing was sent: the report could not be read to check it was submitted to your organisation.',
      { hint: 'Try again shortly.', cause: error },
    );
  }
  if (report === null) {
    throw new BugSecureError(
      'NOT_FOUND',
      'Nothing was sent: the report could not be read to check it was submitted to your organisation. It is not visible to your account.',
      { hint: 'Check the id with list_org_reports, then try again.' },
    );
  }
  assertNotOwnReport(report.reporter.id, context.viewerId);
  return report;
};
