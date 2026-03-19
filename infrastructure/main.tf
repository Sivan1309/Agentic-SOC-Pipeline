terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = "ap-south-2"
}
# S3 Bucket for SOC Logs
# PCI DSS Req 3.5 - Protect stored data
resource "aws_s3_bucket" "soc_logs" {
  bucket = "soc-logs-breadfinancial-${random_id.suffix.hex}"

  tags = {
    Name        = "SOC Logs Bucket"
    Environment = "security"
    Compliance  = "PCI-DSS-3.5"
  }
}

# Random suffix to ensure unique bucket name
resource "random_id" "suffix" {
  byte_length = 4
}

# Encryption - PCI DSS Req 3.5
resource "aws_s3_bucket_server_side_encryption_configuration" "soc_logs" {
  bucket = aws_s3_bucket.soc_logs.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# Versioning - Protect against log deletion
resource "aws_s3_bucket_versioning" "soc_logs" {
  bucket = aws_s3_bucket.soc_logs.id

  versioning_configuration {
    status = "Enabled"
  }
}

# Block Public Access - GLBA Safeguards
resource "aws_s3_bucket_public_access_block" "soc_logs" {
  bucket = aws_s3_bucket.soc_logs.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# CloudTrail - API Audit Trail
# SOX IT Controls - Complete audit trail requirement
resource "aws_cloudtrail" "soc_trail" {
  name                          = "soc-audit-trail"
  s3_bucket_name                = aws_s3_bucket.soc_logs.id
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true

  tags = {
    Name       = "SOC Audit Trail"
    Compliance = "SOX-FFIEC"
  }
}

# S3 Bucket Policy - Allow CloudTrail to write logs
resource "aws_s3_bucket_policy" "soc_logs" {
  bucket = aws_s3_bucket.soc_logs.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AWSCloudTrailAclCheck"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action   = "s3:GetBucketAcl"
        Resource = aws_s3_bucket.soc_logs.arn
      },
      {
        Sid    = "AWSCloudTrailWrite"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action   = "s3:PutObject"
        Resource = "${aws_s3_bucket.soc_logs.arn}/AWSLogs/*"
        Condition = {
          StringEquals = {
            "s3:x-amz-acl" = "bucket-owner-full-control"
          }
        }
      }
    ]
  })
}

# GuardDuty - Automated Threat Detection
# FFIEC Cybersecurity Assessment - Threat Detection
resource "aws_guardduty_detector" "soc" {
  enable = true

  tags = {
    Name       = "SOC GuardDuty Detector"
    Compliance = "FFIEC-PCI-DSS"
  }
}

# CloudWatch Log Group - SOC Monitoring
# PCI DSS Req 10.7 - Retain audit logs minimum 12 months
resource "aws_cloudwatch_log_group" "soc" {
  name              = "/soc/security-events"
  retention_in_days = 365

  tags = {
    Name       = "SOC Security Events"
    Compliance = "PCI-DSS-10.7"
  }
}

# CloudWatch Metric Alarm - GuardDuty High Severity
# FFIEC - Automated alerting on critical findings
resource "aws_cloudwatch_metric_alarm" "guardduty_high" {
  alarm_name          = "guardduty-high-severity-finding"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "1"
  metric_name         = "FindingCount"
  namespace           = "AWS/GuardDuty"
  period              = "300"
  statistic           = "Sum"
  threshold           = "1"
  alarm_description   = "Triggers on any GuardDuty high severity finding - immediate SOC response required"

  dimensions = {
    Severity = "High"
  }

  tags = {
    Name       = "GuardDuty High Severity Alarm"
    Compliance = "FFIEC"
  }
}
