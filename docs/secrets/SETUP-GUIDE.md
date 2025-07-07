# InsureCove AWS Secrets Manager - Complete Setup Guide

## 📋 Overview
This guide provides everything you need to set up and verify AWS Secrets Manager for the InsureCove application.

## 🏗️ Project Structure
```
secrets/
├── export-creation-commands.ps1    # All secret creation commands
├── test/
│   ├── quick-test.ps1              # Quick existence check
│   ├── verify-all-secrets.ps1      # Comprehensive verification
│   ├── run-all-tests.ps1           # Complete test suite
│   ├── secrets-export.json         # Template & documentation
│   └── README.md                   # Detailed usage guide
└── docs/
    └── SETUP-GUIDE.md              # This file
```

## 🚀 Quick Setup (3 Steps)

### Step 1: Create Secrets
```powershell
# Navigate to the secrets directory
cd secrets

# Set your AWS credentials
$env:AWS_ACCESS_KEY_ID = "YOUR_ACCESS_KEY"
$env:AWS_SECRET_ACCESS_KEY = "YOUR_SECRET_KEY"

# Review and run the creation commands
.\export-creation-commands.ps1
```

### Step 2: Verify Setup
```powershell
# Navigate to test directory
cd test

# Run quick verification
.\quick-test.ps1
```

### Step 3: Full Verification
```powershell
# Run comprehensive test suite
.\run-all-tests.ps1 -ExportResults
```

## 📚 Script Reference

### 🔧 Creation Scripts

#### `export-creation-commands.ps1`
- **Purpose**: Contains all AWS CLI commands to create secrets
- **Usage**: Reference and documentation
- **Features**: 
  - Placeholder values (safe for code commit)
  - Formatted commands with descriptions
  - No sensitive information

### 🧪 Verification Scripts

#### `quick-test.ps1`
- **Purpose**: Fast check that all secrets exist
- **Usage**: `.\quick-test.ps1`
- **Features**:
  - Quick existence verification
  - Minimal output
  - Perfect for CI/CD pipelines

#### `verify-all-secrets.ps1`
- **Purpose**: Comprehensive verification with structure validation
- **Usage**: 
  ```powershell
  .\verify-all-secrets.ps1                    # Basic verification
  .\verify-all-secrets.ps1 -Detailed          # Detailed output
  .\verify-all-secrets.ps1 -Export            # Export results to JSON
  ```
- **Features**:
  - Structure validation
  - Missing key detection
  - Detailed reporting
  - JSON export capability

#### `run-all-tests.ps1`
- **Purpose**: Complete test suite running all verifications
- **Usage**: 
  ```powershell
  .\run-all-tests.ps1                         # Run all tests
  .\run-all-tests.ps1 -SkipQuickTest          # Skip quick test
  .\run-all-tests.ps1 -ExportResults          # Export detailed results
  ```
- **Features**:
  - Orchestrates all verification scripts
  - Comprehensive reporting
  - Suitable for regular maintenance

### 📄 Documentation Files

#### `secrets-export.json`
- **Purpose**: Template and documentation
- **Contains**:
  - Secret structures
  - Integration examples
  - Creation commands
  - Verification commands

#### `README.md`
- **Purpose**: Detailed usage instructions
- **Contains**:
  - Setup instructions
  - Troubleshooting guide
  - Advanced usage examples

## 🔑 Expected Secrets

| Secret Name | Type | Purpose |
|-------------|------|---------|
| `insurecove/mistral-api-key` | API Key | Mistral AI API for LLM operations |
| `insurecove/production/database` | Database | Supabase connection credentials |
| `insurecove/production/jwt` | JWT | Token signing configuration |
| `insurecove/production/aws-services` | AWS Services | S3, SES, and service configuration |
| `insurecove/production/security` | Security | Encryption keys and CORS settings |

## 🛠️ Common Use Cases

### Initial Setup
```powershell
# 1. Create all secrets
.\export-creation-commands.ps1

# 2. Verify setup
cd test
.\run-all-tests.ps1 -ExportResults
```

### Regular Maintenance
```powershell
# Monthly verification
.\verify-all-secrets.ps1 -Detailed -Export
```

### CI/CD Pipeline
```powershell
# Quick verification in pipeline
.\quick-test.ps1
if ($LASTEXITCODE -ne 0) {
    Write-Error "Secrets verification failed"
    exit 1
}
```

### Debugging Issues
```powershell
# Get detailed information
.\verify-all-secrets.ps1 -Detailed

# Check specific secret
aws secretsmanager get-secret-value --secret-id "insurecove/production/database"
```

## 🌍 Environment Configuration

### Development Environment
```powershell
$env:AWS_ACCESS_KEY_ID = "dev_access_key"
$env:AWS_SECRET_ACCESS_KEY = "dev_secret_key"
$env:AWS_DEFAULT_REGION = "ap-east-1"
```

### Production Environment
```powershell
# Use IAM roles or AWS profiles for production
aws configure --profile insurecove-prod
```

### Behind Corporate Proxy
```powershell
$env:HTTP_PROXY = "http://proxy.company.com:8080"
$env:HTTPS_PROXY = "http://proxy.company.com:8080"
```

## 🚨 Troubleshooting

### Secret Creation Fails
1. Check AWS credentials
2. Verify IAM permissions
3. Ensure region is correct
4. Check proxy settings if applicable

### Verification Fails
1. Run with `-Detailed` flag for more info
2. Check AWS connectivity
3. Verify secret names and structure
4. Review error messages in script output

### Permission Issues
Required IAM permissions:
- `secretsmanager:CreateSecret`
- `secretsmanager:DescribeSecret`
- `secretsmanager:GetSecretValue`
- `secretsmanager:ListSecrets`

## 📈 Best Practices

### Security
- Never commit actual credentials
- Use environment variables or AWS profiles
- Rotate secrets regularly
- Use least privilege IAM policies

### Maintenance
- Run verification scripts monthly
- Update secrets when services change
- Document any customizations
- Keep backups of secret structures

### Development
- Use separate secrets for dev/test/prod
- Test secret rotation procedures
- Monitor secret usage and costs
- Use descriptive secret names

## 🔄 Integration Examples

### Python FastAPI
```python
import boto3
import json
from botocore.exceptions import ClientError

def get_secret(secret_name: str):
    client = boto3.client('secretsmanager', region_name='ap-east-1')
    try:
        response = client.get_secret_value(SecretId=secret_name)
        return json.loads(response['SecretString'])
    except ClientError as e:
        raise e

# Usage
db_config = get_secret('insurecove/production/database')
```

### Node.js Express
```javascript
const AWS = require('aws-sdk');
const secretsManager = new AWS.SecretsManager({ region: 'ap-east-1' });

async function getSecret(secretName) {
    try {
        const response = await secretsManager.getSecretValue({ 
            SecretId: secretName 
        }).promise();
        return JSON.parse(response.SecretString);
    } catch (error) {
        throw error;
    }
}

// Usage
const dbConfig = await getSecret('insurecove/production/database');
```

## 📞 Support

If you encounter issues:
1. Check this guide and the detailed README
2. Review script output for error messages
3. Verify AWS credentials and permissions
4. Check network connectivity and proxy settings

---

**Note**: All scripts are designed to be safe for code commit and contain no sensitive information. Always use placeholder values and environment variables for actual credentials.
