# Security Monitoring Dashboard — Portfolio Report

## Objective
Develop a defensive monitoring application that turns authentication events
into security metrics and actionable alerts.

## Detection rules
1. Five or more failed authentication events from one source IP within five minutes
   are flagged as potential brute-force activity.
2. A successful login following at least three recent failures from the same IP
   is flagged for investigation.

## Test result
The synthetic dataset contains 11 authentication events:
- 8 failed logins
- 3 successful logins
- 1 source IP producing repeated failures
- 2 generated alerts

## Security interpretation
The detections are indicators, not proof of compromise. A security analyst
would correlate them with user, device, location and other telemetry before
taking action.

## Recommended controls
- Multi-factor authentication
- Strong password policies
- Rate limiting / account lockout where appropriate
- Restricted administrative access
- Centralised logging and alerting
- Investigation of unusual source IPs and authentication patterns

## Skills demonstrated
Python, GUI development, regular-expression parsing, event correlation,
security monitoring, basic detection engineering, analytical reasoning,
technical documentation and security recommendations.
