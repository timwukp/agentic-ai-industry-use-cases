# HIPAA / PHI Handling Policy (Demo Health System)

Document ID: POL-PHI-001 | Effective: 2026-01-01 | Owner: Privacy & Compliance Office

## Protected Health Information (PHI)

PHI includes any individually identifiable health information: name, MRN, dates
(birth, admission, discharge), contact details, insurance IDs, biometric data, full-face
images, and any other unique identifier combined with health data.

## Minimum necessary standard

- Access only the records required for the task at hand. Panel-wide queries require a
  documented population-health purpose.
- AI assistant sessions must reference patients by ID (e.g., PAT-001234), not by full
  name plus date of birth, unless identity verification is the task.

## Access and audit

- All record access is audit-logged with user, timestamp, patient ID, and purpose code.
- Break-glass access (emergency override) triggers same-day compliance review.
- Audit logs are retained for 6 years.

## Disclosure rules

- Verify patient identity with two identifiers before disclosing medical information.
- PHI may not be sent over unencrypted channels (personal email, SMS with clinical
  detail). Appointment reminders may include date/time and provider but not diagnosis.
- Third-party disclosure requires a signed authorization except for treatment, payment,
  and operations (TPO) purposes.

## Breach response

- Suspected breach: report to the Privacy Office within 24 hours.
- Breaches affecting 500+ individuals: HHS and media notification within 60 days.
- All breaches: individual notification without unreasonable delay (max 60 days).

## AI-specific rules

- Simulated/demo data must be labeled as such in any output presented to users.
- Clinical AI output is decision support only; a licensed clinician must review before
  any care decision is made.
- Never include PHI in application logs, traces, or error messages.
