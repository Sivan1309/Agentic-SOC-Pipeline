# Detection Rules

## Overview

This directory contains five Sigma detection rules developed
for a fintech SOC environment. Each rule targets a specific
threat vector relevant to organizations using Okta, Zscaler,
AWS, and Jenkins — mapped to the MITRE ATT&CK framework and
key financial compliance requirements including PCI DSS 4.0,
GLBA Safeguards Rule, FFIEC Guidelines, and SOX.

These rules form a layered detection chain across the complete
attack lifecycle — from initial credential reconnaissance
through identity-based attacks, session hijacking, API
enumeration, and supply chain compromise.

---

## Detection Chain — How Rules Connect
```
Stage 1 → Credential Stuffing        Rule 2 detects
Stage 2 → MFA Fatigue                Rule 1 detects
Stage 2 → AITM Phishing              Rule 3 detects
Stage 3 → API Enumeration            Rule 4 detects
Stage 4 → CI/CD Tampering            Rule 5 detects
```

Catching the attack at Stage 1 prevents all downstream
stages. This is shift left detection — the earlier the
detection fires the lower the blast radius.

---

## Rules

### Rule 1 — Okta Suspicious Login
**File:** `okta_suspicious_login.yml`

**Threat:**
Detects MFA fatigue attacks where an attacker repeatedly
sends Okta Verify push notifications to a victim hoping
they approve out of frustration or by mistake. Also detects
suspicious logins flagged by Okta's own threat engine
including anonymous proxy usage and impossible travel.

**Why it matters:**
Okta is the primary identity provider. One compromised
Okta account provides access to every integrated application
including credit card systems, customer PII, and partner
brand integrations.

**Key Detection Events:**
```
user.mfa.okta_verify.deny_push      → user repeatedly denying push
user.mfa.okta_verify.check.failure  → MFA verification failing
user.mfa.okta_verify.timeout        → push expiring no response
security.threat.detected            → Okta flags suspicious source
user.session.start                  → session created after auth
```

**MITRE:** T1078 — Valid Accounts | T1110 — Brute Force

**Severity:** Critical

**False Positives:**
- Legitimate users traveling internationally
- VPN usage triggering proxy detection
- Administrators testing MFA configurations

---

### Rule 2 — Credential Stuffing OAuth
**File:** `credential_stuffing_oauth.yml`

**Threat:**
Detects high volume automated login attempts against the
OAuth token endpoint using leaked credential lists. Identifies
automation fingerprints including suspicious user agents,
high failed authentication rates, and repeated POST requests
to authentication endpoints.

**Why it matters:**
This is the earliest detection point in the attack chain.
Stopping credential stuffing here prevents the attacker from
identifying valid credentials — making all downstream attacks
impossible. Service accounts authenticating via OAuth have no
MFA — one compromised service account exposes all 100+ partner
brand merchant integrations.

**Key Detection Fields:**
```
request_method: POST          → automated login attempts
url: /oauth/token             → target endpoint
status: 401, 403              → failed authentication
useragent: python-requests    → automation fingerprint
```

**MITRE:** T1110.004 — Credential Stuffing | T1078 — Valid Accounts

**Severity:** High

**False Positives:**
- Load testing tools generating authentication traffic
- Misconfigured applications retrying authentication
- Internal vulnerability scans

---

### Rule 3 — AITM Phishing
**File:** `aitm_phishing.yml`

**Threat:**
Detects Adversary in The Middle phishing attacks using tools
like Evilginx that proxy between the victim and real Okta.
The attacker steals the session cookie after MFA is legitimately
completed — bypassing MFA entirely without the victim's
knowledge.

**Why it matters:**
Unlike MFA fatigue which requires user error, AITM works
against security-aware users. The stolen session cookie
provides full authenticated access without any further
authentication. Early detection in Zscaler proxy logs
is the only automated defense before the cookie is stolen.

**Sigma Limitation:**
```
Full AITM detection requires stateful correlation across
multiple events using KQL (Sentinel), SPL (Splunk), or
EQL (Elastic). This rule covers early-stage phishing domain
detection only via Zscaler proxy logs. For complete session
cookie theft detection including impossible travel implement
correlation rules in your SIEM.
```

**Key Detection Fields:**
```
reason: Phishing              → Zscaler threat classification
url: okta-secure, okta-login  → lookalike identity provider domains
```

**MITRE:** T1557 — Adversary in the Middle | T1539 — Steal Web Session Cookie | T1111 — MFA Interception

**Severity:** High

**False Positives:**
- Security testing tools accessing phishing simulation domains
- Legitimate identity provider redirects
- Users accessing SSO portals from external networks

---

### Rule 4 — Anomalous API Enumeration
**File:** `anomalous_api_enumeration.yml`

**Threat:**
Detects attackers systematically probing AWS API endpoints
to map BFH's attack surface. Identifies repeated AccessDenied
and NoSuchResource errors from the same source across multiple
AWS services — a pattern that never occurs in legitimate usage.

**Why it matters:**
BFH embeds checkout into 100+ brand partner websites via SDK
and API. Successful API enumeration gives attackers a complete
map of available endpoints, authentication weaknesses, and
high value targets before launching precision attacks.
Detecting enumeration early prevents all downstream
precision attacks.

**Key Detection Fields:**
```
errorCode: AccessDenied       → endpoint exists, no permission
errorCode: NoSuchResource     → endpoint does not exist
userIdentity.type: IAMUser    → real human not AWS service
sourceIPAddress               → source of enumeration
```

**Why userIdentity.type matters:**
Filters out legitimate AWS service calls from Lambda, Config,
and GuardDuty — which generate similar error patterns but are
not attacks. Only fires on human or role-based API access.

**MITRE:** T1046 — Network Service Discovery | T1190 — Exploit Public Facing Application

**Severity:** High

**False Positives:**
- Legitimate security scanning tools
- AWS Config and compliance tools
- Developers testing API permissions

---

### Rule 5 — CI/CD Pipeline Tampering
**File:** `cicd_pipeline_tampering.yml`

**Threat:**
Detects unauthorized modifications to Jenkins CI/CD pipelines
including new admin account creation, Jenkinsfile modification,
unauthorized plugin installation, and stored credential access.
These are the four sequential actions an attacker takes to
establish persistent supply chain compromise.

**Why it matters:**
Jenkins controls what gets deployed to production. A compromised
pipeline means malicious code runs automatically on every build
across every environment — affecting every customer and every
partner brand integration simultaneously. This is the highest
impact attack in the chain.

**Key Detection Events:**
```
USER_CREATED + role:admin     → persistent access established
JOB_CONFIG_CHANGED            → pipeline modification
PLUGIN_INSTALLED              → backdoor installation
CREDENTIALS_ACCESSED          → lateral movement preparation
```

**MITRE:** T1195.002 — Supply Chain Compromise | T1072 — Software Deployment Tools

**Severity:** Critical

**False Positives:**
- Legitimate Jenkins administrators performing maintenance
- Approved plugin installations during change windows
- CI/CD automation accounts accessing credentials
- Scheduled pipeline updates via DevOps workflows

---

## Threat Coverage Matrix

| Rule | Threat | Log Source | MITRE | Severity |
|------|--------|------------|-------|----------|
| okta_suspicious_login | MFA Fatigue + Impossible Travel | Okta System | T1078, T1110 | Critical |
| credential_stuffing_oauth | OAuth Brute Force | Web Server | T1110.004, T1078 | High |
| aitm_phishing | Session Cookie Theft | Zscaler Proxy | T1557, T1539, T1111 | High |
| anomalous_api_enumeration | API Surface Mapping | AWS CloudTrail | T1046, T1190 | High |
| cicd_pipeline_tampering | Supply Chain Compromise | Jenkins Audit | T1195.002, T1072 | Critical |

---

## Compliance Mapping

| Rule | PCI DSS 4.0 | GLBA Safeguards | FFIEC | SOX |
|------|-------------|-----------------|-------|-----|
| okta_suspicious_login | Req 8.3 — MFA | Access Controls | Auth Guidance | — |
| credential_stuffing_oauth | Req 6.4 — Web App | Monitoring | Cyber Assessment | — |
| aitm_phishing | Req 4.2 — Transit | Encryption | Auth Guidance | — |
| anomalous_api_enumeration | Req 6.4 — Web App | Monitoring | Cyber Assessment | — |
| cicd_pipeline_tampering | Req 6.3 — Dev | Change Mgmt | — | IT Controls |

---

## Validation

All rules pass YAML validation:
```bash
for file in detections/*.yml; do
    echo "Checking $file"
    python3 -c "import yaml; yaml.safe_load(open('$file')); print('VALID')"
done
```

---

## Author

Sivaram
Senior Security Engineer Candidate
Built as working prototype demonstrating Detection as Code for fintech SOC environment.
