# 🔐 InsureCove AWS Secrets Manager Setup

## 📋 Overview

This document provides a complete guide for setting up AWS Secrets Manager for the InsureCove application, including all necessary secrets and commands for the Hong Kong HA proxy environment.

## 🔑 AWS Configuration Summary

### IAM User Details
- **User Name**: `insurecove-app-user`
- **AWS Account**: `150248166610`
- **User ARN**: `arn:aws:iam::150248166610:user/insurecove-app-user`
- **Region**: `ap-east-1` (Asia Pacific - Hong Kong)

### Credentials Configured
- **AWS_ACCESS_KEY_ID**: `AKIA****************` (replace with your actual access key)
- **AWS_SECRET_ACCESS_KEY**: `************************************` (replace with your actual secret key)
- **Default Region**: `ap-east-1`
- **Output Format**: `json`

## 🚨 Required IAM Permissions

The current IAM user needs the following additional permissions to create secrets:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "SecretsManagerFullAccess",
      "Effect": "Allow",
      "Action": [
        "secretsmanager:CreateSecret",
        "secretsmanager:GetSecretValue",
        "secretsmanager:PutSecretValue",
        "secretsmanager:UpdateSecret",
        "secretsmanager:DeleteSecret",
        "secretsmanager:DescribeSecret",
        "secretsmanager:ListSecrets",
        "secretsmanager:TagResource",
        "secretsmanager:UntagResource"
      ],
      "Resource": [
        "arn:aws:secretsmanager:ap-east-1:150248166610:secret:insurecove/*"
      ]
    }
  ]
}
```

## 🛠️ Installation Commands (Completed)

### 1. AWS CLI Installation
```powershell
# Install AWS CLI with Hong Kong HA proxy
pip install --proxy http://proxy.ha.org.hk:8080 --trusted-host pypi.org --trusted-host pypi.python.org --trusted-host files.pythonhosted.org awscli
```

### 2. AWS CLI Configuration
```powershell
# Configure AWS credentials
python -m awscli configure set aws_access_key_id YOUR_ACCESS_KEY_ID
python -m awscli configure set aws_secret_access_key YOUR_SECRET_ACCESS_KEY
python -m awscli configure set default.region ap-east-1
python -m awscli configure set default.output json
```

### 3. Proxy Configuration
```powershell
# Set proxy environment variables for AWS operations
$env:HTTP_PROXY = "<HTTP_PROXY>"
$env:HTTPS_PROXY = "<HTTPS_PROXY>"
$env:NO_PROXY = "localhost,127.0.0.1,.local"
```

### 4. Verification
```powershell
# Test AWS CLI configuration
$env:HTTP_PROXY = "<HTTP_PROXY>"; $env:HTTPS_PROXY = "<HTTPS_PROXY>"; python -m awscli sts get-caller-identity
```

## 🔐 Secrets to Create

### 1. Mistral AI API Key
**Secret Name**: `insurecove/mistral-api-key`
**Description**: Mistral AI API key for InsureCove application
**Secret Value**: JSON format with API key

```powershell
# Command to create Mistral API secret
$env:HTTP_PROXY = "<HTTP_PROXY>"; $env:HTTPS_PROXY = "<HTTPS_PROXY>"; python -m awscli secretsmanager create-secret --name "insurecove/mistral-api-key" --description "Mistral AI API key for InsureCove application" --secret-string '{\"api_key\": \"YOUR_MISTRAL_API_KEY_HERE\"}' --region ap-east-1
```

### 2. Supabase Database Credentials
**Secret Name**: `insurecove/production/database`
**Description**: InsureCove Supabase database credentials
**Secret Value**: JSON format with database connection details

```powershell
# Command to create Supabase database secret
$env:HTTP_PROXY = "<HTTP_PROXY>"; $env:HTTPS_PROXY = "<HTTPS_PROXY>"; python -m awscli secretsmanager create-secret --name "insurecove/production/database" --description "InsureCove Supabase database credentials" --secret-string '{\"url\": \"https://qdlnzksichidgdqdtkkl.supabase.co\", \"anon_key\": \"YOUR_SUPABASE_ANON_KEY\", \"service_key\": \"YOUR_SUPABASE_SERVICE_KEY\", \"db_password\": \"YOUR_DB_PASSWORD\"}' --region ap-east-1
```

### 3. JWT Signing Secret
**Secret Name**: `insurecove/production/jwt`
**Description**: InsureCove JWT signing secret
**Secret Value**: JSON format with JWT configuration

```powershell
# Command to create JWT secret
$env:HTTP_PROXY = "<HTTP_PROXY>"; $env:HTTPS_PROXY = "<HTTPS_PROXY>"; python -m awscli secretsmanager create-secret --name "insurecove/production/jwt" --description "InsureCove JWT signing secret" --secret-string '{\"secret_key\": \"YOUR_256_BIT_SECRET_KEY\", \"algorithm\": \"HS256\", \"issuer\": \"insurecove-api\", \"audience\": \"insurecove-clients\"}' --region ap-east-1
```

### 4. AWS Service Configuration
**Secret Name**: `insurecove/production/aws-services`
**Description**: InsureCove AWS service configurations
**Secret Value**: JSON format with AWS service settings

```powershell
# Command to create AWS services secret
$env:HTTP_PROXY = "<HTTP_PROXY>"; $env:HTTPS_PROXY = "<HTTPS_PROXY>"; python -m awscli secretsmanager create-secret --name "insurecove/production/aws-services" --description "InsureCove AWS service configurations" --secret-string '{\"ses_from_email\": \"noreply@insurecove.com\", \"ses_from_name\": \"InsureCove\", \"s3_bucket\": \"insurecove-docs-archive-hk\", \"sms_sender_id\": \"InsureCove\"}' --region ap-east-1
```

### 5. API Integration Keys
**Secret Name**: `insurecove/production/api-keys`
**Description**: Third-party API integration keys
**Secret Value**: JSON format with various API keys

```powershell
# Command to create API keys secret
$env:HTTP_PROXY = "<HTTP_PROXY>"; $env:HTTPS_PROXY = "<HTTPS_PROXY>"; python -m awscli secretsmanager create-secret --name "insurecove/production/api-keys" --description "Third-party API integration keys" --secret-string '{\"google_maps_api_key\": \"YOUR_GOOGLE_MAPS_KEY\", \"twilio_auth_token\": \"YOUR_TWILIO_TOKEN\", \"sendgrid_api_key\": \"YOUR_SENDGRID_KEY\"}' --region ap-east-1
```

## 📋 Management Commands

### List All Secrets
```powershell
# List all InsureCove secrets
$env:HTTP_PROXY = "<HTTP_PROXY>"; $env:HTTPS_PROXY = "<HTTPS_PROXY>"; python -m awscli secretsmanager list-secrets --filters Key=name,Values=insurecove --region ap-east-1
```

### Get Secret Value
```powershell
# Get a specific secret value
$env:HTTP_PROXY = "<HTTP_PROXY>"; $env:HTTPS_PROXY = "<HTTPS_PROXY>"; python -m awscli secretsmanager get-secret-value --secret-id "insurecove/mistral-api-key" --region ap-east-1
```

### Update Secret Value
```powershell
# Update a secret value
$env:HTTP_PROXY = "<HTTP_PROXY>"; $env:HTTPS_PROXY = "<HTTPS_PROXY>"; python -m awscli secretsmanager update-secret --secret-id "insurecove/mistral-api-key" --secret-string '{\"api_key\": \"NEW_API_KEY_HERE\"}' --region ap-east-1
```

### Describe Secret
```powershell
# Get secret metadata
$env:HTTP_PROXY = "<HTTP_PROXY>"; $env:HTTPS_PROXY = "<HTTPS_PROXY>"; python -m awscli secretsmanager describe-secret --secret-id "insurecove/mistral-api-key" --region ap-east-1
```

## 🚨 Current Issue

The IAM user `insurecove-app-user` currently **lacks permissions** to create secrets in AWS Secrets Manager. The following error was encountered:

```
AccessDeniedException: User: arn:aws:iam::150248166610:user/insurecove-app-user is not authorized to perform: secretsmanager:CreateSecret
```

## 🔧 Resolution Steps

1. **Contact AWS Administrator** to add the required IAM permissions
2. **Or create a new IAM policy** with the permissions shown above
3. **Attach the policy** to the `insurecove-app-user`
4. **Re-run the secret creation commands** once permissions are granted

## 📊 Cost Estimate

### AWS Secrets Manager Pricing (ap-east-1)
- **Secret Storage**: $0.40 per secret per month
- **API Calls**: $0.05 per 10,000 requests
- **Estimated Monthly Cost**: $2.00 - $3.00 for 5-7 secrets

### Expected Secrets
1. `insurecove/mistral-api-key` - $0.40/month
2. `insurecove/production/database` - $0.40/month
3. `insurecove/production/jwt` - $0.40/month
4. `insurecove/production/aws-services` - $0.40/month
5. `insurecove/production/api-keys` - $0.40/month

**Total**: ~$2.00/month + API call charges

## 🔄 Automation Scripts

### Daily Secret Check Script
```powershell
# Save as: check-secrets.ps1
$env:HTTP_PROXY = "<HTTP_PROXY>"
$env:HTTPS_PROXY = "<HTTPS_PROXY>"

Write-Host "🔍 Checking InsureCove secrets..." -ForegroundColor Green
python -m awscli secretsmanager list-secrets --filters Key=name,Values=insurecove --region ap-east-1 --output table
```

### Secret Rotation Script
```powershell
# Save as: rotate-jwt-secret.ps1
$env:HTTP_PROXY = "<HTTP_PROXY>"
$env:HTTPS_PROXY = "<HTTPS_PROXY>"

$newJwtSecret = -join ((1..64) | ForEach {[char]((65..90) + (97..122) | Get-Random)})
Write-Host "🔄 Rotating JWT secret..." -ForegroundColor Yellow
python -m awscli secretsmanager update-secret --secret-id "insurecove/production/jwt" --secret-string "{\"secret_key\": \"$newJwtSecret\", \"algorithm\": \"HS256\", \"issuer\": \"insurecove-api\", \"audience\": \"insurecove-clients\"}" --region ap-east-1
Write-Host "✅ JWT secret rotated successfully!" -ForegroundColor Green
```

## 📞 Support Information

- **AWS Account**: 150248166610
- **Region**: ap-east-1 (Asia Pacific - Hong Kong)
- **Proxy**: <HTTP_PROXY>
- **IAM User**: insurecove-app-user
- **Primary Contact**: AWS Administrator for permission escalation

## 🎯 Next Steps

1. **Obtain IAM permissions** for secret creation
2. **Create all required secrets** using the commands above
3. **Update application code** to use AWS Secrets Manager
4. **Set up monitoring** for secret access
5. **Implement rotation schedule** for sensitive secrets

---

*This documentation was generated on July 3, 2025, for the InsureCove application deployment in the Hong Kong HA environment.*
