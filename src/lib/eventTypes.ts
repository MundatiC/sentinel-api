// Event type names shared by the API, the scanner and the dashboard.
export const EventTypes = {
  LoginFailed: 'auth.login_failed',
  LoginSuccess: 'auth.login_success',
  InjectionAttempt: 'http.injection_attempt',
  ScanFindingCritical: 'scan.finding_critical',
} as const;
