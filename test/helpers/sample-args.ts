/** Minimal valid arguments per tool, so a call gets past input validation. */
export const SAMPLE_ARGS: Record<string, Record<string, unknown>> = {
  get_program: { id: 'p1' },
  get_researcher_profile: { username: 'ada' },
  verify_certificate: { publicToken: 'Q2VydGlmaWNhdGVUb2tlbg' },
  search: { query: 'xss' },
  get_report: { reportId: 'r1' },
  get_org_report: { reportId: 'r1' },
  get_org_report_stats: { organizationId: 'o1' },
  get_program_stats: { programId: 'p1' },
  check_duplicates: { programId: 'p1', title: 'Stored XSS in the profile page', description: 'd' },
  submit_report: {
    programId: 'p1',
    title: 'Stored XSS in profile bio',
    severity: 'HIGH',
    description: 'The profile bio is rendered without escaping on the public profile page.',
    stepsToReproduce: '1. Set the bio. 2. Open the profile.',
    impact: 'Session theft.',
  },
  add_report_comment: { reportId: 'r1', content: 'hi' },
  raise_appeal: {
    reportId: 'r1',
    adjudicationId: 'a1',
    grounds: 'The CVSS vector ignores the scope change.',
  },
  update_report_status: { reportId: 'r1', status: 'IN_TRIAGE' },
  add_triage_comment: { reportId: 'r1', content: 'hi' },
  list_org_certificates: { organizationId: 'o1' },
  get_program_terms: { kind: 'PLATFORM_RESEARCHER' },
  mark_notifications_read: { ids: ['n1'] },
  update_my_profile: { bio: 'I hunt stored XSS.' },
  save_disclosure_draft: {
    reportId: 'r1',
    revision: 3,
    title: 'Stored XSS in profile bio',
    summary: 'The bio was rendered without escaping.',
    writeup: 'Setting the bio to a script tag ran it for every visitor of the profile.',
    creditResearcher: true,
  },
  assign_report: { reportId: 'r1' },
  grade_report: {
    reportId: 'r1',
    vrtNodeId: 'cross_site_scripting_xss.stored.non_privileged_user_to_anyone',
    severity: 'HIGH',
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N',
    cvssScore: 8.1,
    reasoning: 'Stored XSS reachable by any visitor of the public profile; session cookies are not HttpOnly.',
  },
};

/** Write tools that act on the organisation's side (the signed-in user is not the reporter). */
export const ORG_SIDE_WRITE_TOOLS: ReadonlySet<string> = new Set([
  'update_report_status',
  'add_triage_comment',
  'assign_report',
  'grade_report',
]);

/**
 * Organisation-side writes that change a report (its status, its grade, who triages it): the report is
 * always read first, to check it is not the caller's own (orgSideReport), and a caller who cannot be
 * told from the reporter is refused.
 */
export const REPORT_CHANGING_ORG_TOOLS: ReadonlySet<string> = new Set([
  'update_report_status',
  'assign_report',
  'grade_report',
]);

/**
 * Write tools that read the report they act on before asking for, or sending, the write — always
 * (REPORT_CHANGING_ORG_TOOLS) or when the token holds their side's read scope (the comment tools,
 * lookupReport) — and refuse, registering nothing, when that read cannot complete (readReportRef).
 */
export const REPORT_READING_WRITE_TOOLS: ReadonlySet<string> = new Set([
  ...REPORT_CHANGING_ORG_TOOLS,
  'add_report_comment',
  'add_triage_comment',
]);

/** The mutation each write tool sends. */
export const WRITE_OPERATION: Readonly<Record<string, string>> = {
  submit_report: 'SubmitReport',
  add_report_comment: 'AddReportComment',
  raise_appeal: 'RaiseAppeal',
  update_report_status: 'UpdateReportStatus',
  add_triage_comment: 'AddTriageComment',
  grade_report: 'GradeReport',
  mark_notifications_read: 'MarkNotificationRead',
  update_my_profile: 'UpdateMyProfile',
  save_disclosure_draft: 'SaveDisclosureDraft',
  assign_report: 'AssignReport',
};

/** The API operation each write tool's payload registers for approval (its mutation's root field). */
export const APPROVED_OPERATION: Readonly<Record<string, string>> = {
  submit_report: 'submitReport',
  add_report_comment: 'addReportComment',
  raise_appeal: 'raiseAppeal',
  update_report_status: 'updateReportStatus',
  add_triage_comment: 'addReportComment',
  grade_report: 'adjudicateReport',
  mark_notifications_read: 'markNotificationAsRead',
  update_my_profile: 'updateResearcherProfile',
  save_disclosure_draft: 'saveReportDisclosure',
  assign_report: 'assignTriageAnalyst',
};
