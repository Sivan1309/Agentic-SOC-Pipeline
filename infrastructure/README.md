# Infrastructure as Code — SOC Environment

## Overview
Terraform module provisioning a security hardened SOC
logging environment on AWS. Every resource is mapped
to a specific compliance control.

## Resources

| Resource | Purpose | Compliance |
|----------|---------|------------|
| aws_s3_bucket | SOC log storage | PCI DSS 3.5 |
| aws_s3_bucket_versioning | Log deletion protection | FFIEC |
| aws_s3_bucket_encryption | AES256 encryption at rest | PCI DSS 3.5 |
| aws_s3_bucket_public_access_block | Prevent exposure | GLBA |
| aws_s3_bucket_policy | CloudTrail write access | SOX |
| aws_cloudtrail | API audit trail all regions | SOX, FFIEC |
| aws_guardduty_detector | Automated threat detection | FFIEC, PCI DSS |
| aws_cloudwatch_log_group | 365 day log retention | PCI DSS 10.7 |
| aws_cloudwatch_metric_alarm | High severity alerting | FFIEC |

## Usage

Initialize:
```bash
terraform init
```

Preview changes:
```bash
terraform plan
```

Deploy:
```bash
terraform apply
```

## Compliance Mapping

PCI DSS 4.0:
- Req 3.5 → Encryption at rest on all log storage
- Req 10.7 → 365 day log retention in CloudWatch

GLBA Safeguards:
- Block public access on all S3 buckets
- Encryption of customer data logs

FFIEC Guidelines:
- Multi region CloudTrail coverage
- Automated alerting on high severity findings
- GuardDuty continuous threat monitoring

SOX IT Controls:
- Complete API audit trail via CloudTrail
- Log file validation enabled
- Tamper evident logging
