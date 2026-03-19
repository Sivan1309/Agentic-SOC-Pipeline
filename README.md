# Agentic SOC Pipeline
### A Working Prototype of Modern Security Operations for Fintech

---

## Overview

This project demonstrates a fully integrated Security Operations Center (SOC) pipeline built around four pillars of modern security engineering — Detection as Code, Infrastructure as Code, Agentic AI SOC, and Policy as Code.

Every component is mapped to real threat vectors targeting fintech environments, aligned to compliance frameworks including PCI DSS 4.0, GLBA Safeguards Rule, FFIEC Guidelines, and SOX IT Controls.

This is not a theoretical exercise. Every rule runs. Every policy enforces. Every agent triages. Every infrastructure resource deploys.

---

## Architecture
```
Threat Actor
     ↓
Detection as Code (Sigma Rules)
Detects attack patterns across identity, API, and CI/CD layers
     ↓
Infrastructure as Code (Terraform)
Provisions secure SOC environment — CloudTrail, GuardDuty, S3, CloudWatch
     ↓
Agentic AI SOC (Python + Claude AI)
Automatically triages GuardDuty findings
Maps to MITRE ATT&CK
Recommends Contain / Escalate / Dismiss
     ↓
Policy as Code (OPA + Conftest)
Enforces compliance before any infrastructure deploys
Blocks violations at CI/CD pipeline level
```

---

## Project Structure
```
Agentic-SOC-Pipeline/
├── detections/                    ← Detection as Code
│   ├── okta_suspicious_login.yml
│   ├── credential_stuffing_oauth.yml
│   ├── aitm_phishing.yml
│   ├── anomalous_api_enumeration.yml
│   ├── cicd_pipeline_tampering.yml
│   └── README.md
│
├── infrastructure/                ← Infrastructure as Code
│   ├── main.tf
│   └── README.md
│
├── agent/                         ← Agentic AI SOC
│   ├── agent.py
│   ├── mock_finding.json
│   ├── mock_finding_2.json
│   ├── mock_finding_3.json
│   └── triage_report.json
│
├── policies/                      ← Policy as Code
│   ├── s3_encryption.rego
│   ├── mfa_admin.rego
│   ├── no_public_ssh.rego
│   └── cloudtrail_enabled.rego
│
└── docs/                          ← Documentation
    └── policy_results.txt
```

---

## Pillar 1 — Detection as Code

### What It Is
Detection rules written as version-controlled YAML files using the Sigma standard. Rules can be converted to any SIEM query language automatically — Splunk SPL, Elastic EQL, Microsoft Sentinel KQL — using pySigma.

### Why It Matters
Traditional SOC teams write detection rules manually inside SIEM GUIs. Those rules are not version controlled, not peer reviewed, not tested, and not portable. Detection as Code treats detections like software — every rule is reviewed, tested, and deployed through a pipeline.

### The Attack Chain

These five rules are not independent. They form a layered detection chain across the complete attack lifecycle:
```
Stage 1 → Credential Stuffing        Rule 2 — earliest detection point
Stage 2 → MFA Fatigue                Rule 1 — identity layer attack
Stage 2 → AITM Phishing              Rule 3 — session hijacking
Stage 3 → API Enumeration            Rule 4 — reconnaissance
Stage 4 → CI/CD Tampering            Rule 5 — supply chain compromise
```

Catching the attack at Stage 1 prevents all downstream stages. This is shift left detection — the earlier the detection fires the lower the blast radius and the lower the cost of response.

### Rules

**Rule 1 — Okta Suspicious Login**
Detects MFA fatigue attacks where an attacker repeatedly sends Okta Verify push notifications hoping the victim approves out of frustration. Also detects logins from suspicious proxy sources flagged by Okta's threat engine.

Key events: `user.mfa.okta_verify.deny_push`, `user.mfa.okta_verify.check.failure`, `security.threat.detected`

MITRE: T1078 Valid Accounts | T1110 Brute Force | Severity: Critical

---

**Rule 2 — Credential Stuffing OAuth**
Detects high volume automated login attempts against the OAuth token endpoint using leaked credential lists. Identifies automation fingerprints including suspicious user agents and repeated 401 responses.

Why service accounts matter: BFH's 100+ partner brand integrations authenticate via OAuth service accounts with no MFA. One compromised service account exposes all partner merchant checkout flows.

MITRE: T1110.004 Credential Stuffing | Severity: High

---

**Rule 3 — AITM Phishing**
Detects Adversary in The Middle attacks using tools like Evilginx that proxy between the victim and real Okta. The attacker steals the session cookie after MFA is legitimately completed — bypassing MFA entirely.

Important limitation: Sigma is event-based and cannot perform stateful correlation. This rule detects early phishing domain indicators in Zscaler proxy logs only. Full impossible travel detection requires KQL or SPL in a SIEM. This limitation is documented directly in the rule.

MITRE: T1557 Adversary in the Middle | T1539 Steal Web Session Cookie | T1111 MFA Interception | Severity: High

---

**Rule 4 — Anomalous API Enumeration**
Detects attackers systematically probing AWS API endpoints to map BFH's attack surface. Identifies repeated AccessDenied and NoSuchResource errors — a pattern that never occurs in legitimate usage.

Why userIdentity.type matters: Filters out legitimate AWS service calls from Lambda, Config, and GuardDuty which generate similar error patterns. Only fires on human or role-based access.

MITRE: T1046 Network Service Discovery | T1190 Exploit Public Facing Application | Severity: High

---

**Rule 5 — CI/CD Pipeline Tampering**
Detects the four sequential actions an attacker takes to establish persistent supply chain compromise in Jenkins: admin account creation, Jenkinsfile modification, plugin installation, and credential access.

Why this is critical: Jenkins controls what gets deployed to production. A compromised pipeline means malicious code runs automatically on every build — affecting every customer and every partner brand integration simultaneously.

MITRE: T1195.002 Supply Chain Compromise | T1072 Software Deployment Tools | Severity: Critical

### Compliance Mapping

| Rule | PCI DSS 4.0 | GLBA | FFIEC | SOX |
|------|-------------|------|-------|-----|
| okta_suspicious_login | Req 8.3 | Access Controls | Auth Guidance | — |
| credential_stuffing_oauth | Req 6.4 | Monitoring | Cyber Assessment | — |
| aitm_phishing | Req 4.2 | Encryption | Auth Guidance | — |
| anomalous_api_enumeration | Req 6.4 | Monitoring | Cyber Assessment | — |
| cicd_pipeline_tampering | Req 6.3 | Change Mgmt | — | IT Controls |

---

## Pillar 2 — Infrastructure as Code

### What It Is
A Terraform module that provisions a complete security hardened SOC environment on AWS with a single command. Every resource is documented with the compliance control it satisfies.

### Why It Matters
Manual infrastructure configuration is error prone, inconsistent, and undocumented. Infrastructure as Code ensures every environment is identical, every change is tracked in version control, and every resource is compliant by default.

### Resources Provisioned

| Resource | Purpose | Compliance |
|----------|---------|------------|
| aws_s3_bucket | SOC log storage | PCI DSS 3.5 |
| aws_s3_bucket_versioning | Log deletion protection | FFIEC |
| aws_s3_bucket_encryption | AES256 at rest | PCI DSS 3.5 |
| aws_s3_bucket_public_access_block | Prevent public exposure | GLBA |
| aws_s3_bucket_policy | CloudTrail write permission | SOX |
| aws_cloudtrail | API audit trail all regions | SOX, FFIEC |
| aws_guardduty_detector | Automated threat detection | FFIEC, PCI DSS |
| aws_cloudwatch_log_group | 365 day log retention | PCI DSS 10.7 |
| aws_cloudwatch_metric_alarm | High severity alerting | FFIEC |

### Usage
```bash
cd infrastructure
terraform init
terraform plan
terraform apply
```

### Design Decisions

**S3 with encryption, versioning and public access block:**
CloudTrail logs contain every API call in the AWS account. Without encryption an attacker who gains S3 access reads all detection patterns. Without versioning an attacker deletes logs to cover tracks. Without public access block one misconfiguration exposes the entire audit history.

**CloudTrail multi-region with log file validation:**
BFH operates across multiple AWS regions. A single region trail misses API calls in other regions — an attacker exploits this gap deliberately. Log file validation detects if logs were tampered with after delivery.

**GuardDuty:**
Continuously analyzes CloudTrail, VPC flow logs and DNS logs for threat patterns. Generates structured findings that feed directly into the agentic triage layer.

**365 day CloudWatch retention:**
PCI DSS Requirement 10.7 mandates audit log retention for a minimum of 12 months with 3 months immediately available. 365 days satisfies both requirements in a single resource.

---

## Pillar 3 — Agentic AI SOC

### What It Is
A Python based SOC triage agent that automatically processes GuardDuty security findings, enriches them with context, maps them to MITRE ATT&CK, and recommends a structured response action.

### Why It Matters
SOC teams are overwhelmed with alerts. Tier 1 analysts spend most of their time on repetitive triage tasks — reading alerts, assessing severity, deciding what to do. An agentic layer automates this entirely, allowing analysts to focus on complex investigations and threat hunting.

### How It Works
```
Input: GuardDuty finding JSON
       ↓
parse_finding()
Reads and validates the finding structure
Ensures required fields exist
       ↓
build_prompt()
Constructs a structured SOC analyst prompt
Injects finding details, resource context, action details
Specifies exact JSON output format required
       ↓
call_llm_api()
Sends prompt to Claude AI
Returns structured analysis
       ↓
parse_response()
Extracts triage decision from LLM response
Handles malformed responses gracefully
Defaults to Escalate if parsing fails — safety first
       ↓
Output: triage_report.json
```

### Agent Output Structure
```json
{
  "finding_id": "abc123",
  "severity_assessment": "Critical",
  "severity_reasoning": "detailed reasoning",
  "mitre_technique": "T1526 - Gather Victim Account Information",
  "mitre_tactic": "Reconnaissance",
  "attack_summary": "what the attacker is doing",
  "recommended_action": "Escalate",
  "action_reasoning": "why this action is recommended",
  "immediate_steps": [
    "step 1",
    "step 2",
    "step 3"
  ],
  "analyst_notes": "additional SOC context"
}
```

### Usage
```bash
cd agent
source ~/soc-env/bin/activate
export ANTHROPIC_API_KEY="your-key-here"

python3 agent.py mock_finding.json
python3 agent.py mock_finding_2.json
python3 agent.py mock_finding_3.json
```

### Test Findings Included
```
mock_finding.json    →  IAM enumeration from malicious Russian IP
                        service account compromise
                        GuardDuty severity 8.0

mock_finding_2.json  →  Cryptocurrency mining on EC2
                        known mining pool domain query
                        GuardDuty severity 5.0

mock_finding_3.json  →  IAM reconnaissance by internal user
                        unusual permission enumeration
                        GuardDuty severity 3.0
```

---

## Pillar 4 — Policy as Code

### What It Is
Four OPA Rego policies that automatically enforce compliance requirements against Terraform plans before any infrastructure deploys. Run using Conftest in CI/CD pipelines.

### Why It Matters
AWS Config can detect compliance violations after deployment. Policy as Code catches them before deployment — at the code commit stage. This is shift left compliance. Zero violations reach production. Compliance becomes continuous rather than periodic.

### Policies

**Policy 1 — S3 Encryption Required**
File: `s3_encryption.rego`
Compliance: PCI DSS Req 3.5 — Protect stored cardholder data
Blocks any S3 bucket deployment without server side encryption configured.

**Policy 2 — MFA on IAM Admin Roles**
File: `mfa_admin.rego`
Compliance: GLBA Safeguards Rule — Access Controls
Blocks IAM user configurations that do not enforce MFA.

**Policy 3 — No Public SSH or RDP**
File: `no_public_ssh.rego`
Compliance: FFIEC Network Security Guidelines
Blocks any security group rule exposing port 22 or 3389 to 0.0.0.0/0.

**Policy 4 — CloudTrail All Regions**
File: `cloudtrail_enabled.rego`
Compliance: SOX IT Controls — Complete audit trail requirement
Blocks CloudTrail configurations that are not multi-region or do not have log file validation enabled.

### Usage
```bash
cd infrastructure
terraform plan -out=tfplan.binary
terraform show -json tfplan.binary > tfplan.json
cd ..

conftest test infrastructure/tfplan.json --policy policies/ --namespace terraform.aws.s3
conftest test infrastructure/tfplan.json --policy policies/ --namespace terraform.aws.cloudtrail
conftest test infrastructure/tfplan.json --policy policies/ --namespace terraform.aws.security
conftest test infrastructure/tfplan.json --policy policies/ --namespace terraform.aws.iam
```

### Evidence

Policy test results are captured in `docs/policy_results.txt`.

The intentional failure test demonstrates a deliberately unencrypted S3 bucket being blocked:
```
FAIL - infrastructure/tfplan.json - terraform.aws.s3
S3 bucket 'bad_bucket' must have encryption enabled. PCI DSS Req 3.5
1 test, 0 passed, 0 warnings, 1 failure, 0 exceptions
```

---

## Threat Intelligence Context

### Why These Threats Were Chosen

This project targets the specific threat landscape of a fintech company embedding financial services into 100+ partner brand websites via SDK and API integrations.

**Identity attacks (Rules 1, 2, 3):**
The primary identity provider is the highest value target. One compromised identity gives access to every integrated application — credit processing, customer PII, partner integrations, and internal tools.

**API enumeration (Rule 4):**
The merchant SDK exposes API endpoints across 100+ partner websites. Attackers enumerate these endpoints to map the attack surface before launching precision attacks against payment processing and customer data endpoints.

**Supply chain attack (Rule 5):**
The CI/CD pipeline is the ultimate high value target. Compromising Jenkins means malicious code is automatically deployed to production — affecting every customer and every partner brand integration simultaneously without detection.

### MITRE ATT&CK Coverage
```
Initial Access      →  T1078, T1195.002
Credential Access   →  T1110, T1110.004, T1557, T1539, T1111
Discovery           →  T1046, T1190
Persistence         →  T1072
Collection          →  T1539
```

---

## Tech Stack

| Tool | Purpose | Why Chosen |
|------|---------|------------|
| Sigma | Detection rule format | SIEM agnostic — converts to any platform |
| Terraform | Infrastructure provisioning | Industry standard IaC for AWS |
| Python | SOC triage agent | Rapid development, rich library ecosystem |
| Anthropic Claude | AI triage engine | State of the art reasoning for security analysis |
| OPA / Rego | Policy enforcement | Native integration with Terraform and CI/CD |
| Conftest | Policy testing | Runs OPA policies against Terraform plans |
| AWS GuardDuty | Threat detection | Native AWS — analyzes CloudTrail automatically |
| AWS CloudTrail | Audit logging | Complete API activity record — source of truth |

---

## Setup

**Prerequisites:**
```
Python 3.11+
Terraform CLI
OPA CLI
Conftest
AWS CLI configured
Anthropic API key
```

**Install dependencies:**
```bash
source ~/soc-env/bin/activate
pip install anthropic
```

**Set environment variable:**
```bash
export ANTHROPIC_API_KEY="your-key-here"
```

**Run detection validation:**
```bash
for file in detections/*.yml; do
    python3 -c "import yaml; yaml.safe_load(open('$file')); print(f'VALID: $file')"
done
```

**Run infrastructure plan:**
```bash
cd infrastructure
terraform init
terraform plan
```

**Run agent:**
```bash
cd agent
python3 agent.py mock_finding.json
```

**Run policy checks:**
```bash
conftest test infrastructure/tfplan.json --policy policies/ --namespace terraform.aws.s3
```

---

## Author

Sivaram
Senior Security Engineer
Built as working prototype demonstrating Detection as Code,
Infrastructure as Code, Agentic AI SOC, and Policy as Code
for a fintech SOC environment — mapped to real threat vectors
and compliance requirements.
