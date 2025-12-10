# AWS Resource Tagger

Tag AWS resources with their primary identifiers. Includes a web UI to browse CloudFormation resource schemas.

## Quick Start

1. **Fetch AWS schemas** (requires Python 3 with `requests`):
   ```bash
   uv run fetch_schemas.py
   ```

2. **Open the web page**:
   ```bash
   # Using Python's built-in server
   uv run python -m http.server 8000
   # Then open http://localhost:8000
   ```

## Features

- Lists all 1400+ AWS CloudFormation resource types
- Shows primary and additional identifiers for each resource
- Column-level search filters for:
  - Type Name (e.g., `AWS::EC2::Instance`)
  - Service (e.g., `EC2`, `S3`, `Lambda`)
  - Resource (e.g., `Instance`, `Bucket`, `Function`)
  - Primary Identifier
  - Additional Identifiers
  - Description
- Global search across all columns
- Highlights composite identifiers (resources with multi-property primary keys)

## JSON Data

The `aws_resources.json` file contains all resource data and can be used programmatically:

```javascript
const response = await fetch('https://your-site.netlify.app/aws_resources.json');
const data = await response.json();
console.log(data.resources); // Array of 1400+ resources
```

Each resource has the following structure:

```json
{
  "typeName": "AWS::EC2::Instance",
  "provider": "AWS",
  "service": "EC2",
  "resource": "Instance",
  "description": "Resource Type definition for AWS::EC2::Instance",
  "primaryIdentifier": ["InstanceId"],
  "additionalIdentifiers": []
}
```

## Tagging Resources

The `tag_resources.py` script automatically tags AWS resources with their primary identifier.

### Prerequisites

AWS credentials must be configured via environment variables, `~/.aws/credentials`, or IAM role.

### Usage

```bash
# Set the tag key (required)
export AWS_IDENTIFIER_TAG_KEY="ResourceIdentifier"

# Tag all supported resources in all services
uv run tag_resources.py

# Dry run - see what would be tagged without making changes
uv run tag_resources.py --dry-run

# Tag specific service(s) only
uv run tag_resources.py --service EC2
uv run tag_resources.py --service EC2 --service S3 --service Lambda

# Specify AWS region
uv run tag_resources.py --region us-west-2

# List all supported services and resource types
uv run tag_resources.py --list-services
```

### Options

| Option | Description |
|--------|-------------|
| `--dry-run` | Show what would be tagged without making changes |
| `--service SERVICE` | Tag only specific service(s). Can be repeated for multiple services |
| `--region REGION` | AWS region (default: `us-east-1` or `AWS_DEFAULT_REGION` env var) |
| `--list-services` | List all supported services and resource types, then exit |

### Supported Services

The script supports 40+ AWS services including:

- **Compute**: EC2, Lambda, ECS, EKS, Batch, EMR
- **Storage**: S3, EFS, FSx
- **Database**: RDS, DynamoDB, ElastiCache, Redshift, OpenSearch
- **Networking**: VPC, ELB/ELBv2, Route53, CloudFront, API Gateway
- **Security**: IAM, KMS, ACM, Secrets Manager, WAFv2
- **Integration**: SNS, SQS, EventBridge, Step Functions
- **DevOps**: CodeBuild, CodePipeline, CodeCommit, ECR, CloudFormation
- **Analytics**: Kinesis, Firehose, Glue, Athena
- **ML**: SageMaker
- **Other**: CloudWatch, Logs, SSM, Cognito, AppSync, Backup

Run `uv run tag_resources.py --list-services` for the complete list.

### How It Works

1. The script discovers resources using each service's native AWS API
2. For each resource found, it applies a tag where:
   - **Key**: Value of `AWS_IDENTIFIER_TAG_KEY` environment variable
   - **Value**: The resource's primary identifier (e.g., instance ID, bucket name)
3. Tagging is attempted via the Resource Groups Tagging API first, with service-specific fallbacks

### Example Output

```
Tag key: ResourceIdentifier
Region: us-east-1
Dry run: False
Services: 40
============================================================

EC2:
  Instance...
    Tagged i-0abc123def456
    Tagged i-0xyz789ghi012
  Volume...
    Tagged vol-0abc123def456

S3:
  Bucket...
    Tagged my-app-bucket
    Tagged my-logs-bucket

============================================================
Summary:
  Tagged: 42
  Errors: 0
  Skipped: 0
```

## Deployment

This is a static site that can be deployed to any static hosting provider:

- **Netlify**: Drag and drop the folder or connect to Git
- **Vercel**: `vercel deploy`
- **GitHub Pages**: Push to a `gh-pages` branch
- **S3 + CloudFront**: Upload files to S3 bucket

## Data Source

Data is sourced from [AWS CloudFormation Resource Provider Schemas](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/resource-type-schemas.html).
