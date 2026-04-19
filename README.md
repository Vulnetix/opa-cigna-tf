# opa-cigna-tf

Vulnetix CLI-compatible OPA custom rules for Terraform IaC security checks, inspired by the [Cigna confectionery](https://github.com/cigna/confectionery) Terraform rules.

## Clean-room development

These rules were produced using a **clean-room approach**. The original Cigna confectionery rules were consulted only to understand the *intent* of each security check. All Rego implementations were then written independently from scratch, targeting the Vulnetix CLI's text-scanning input model (`input.file_contents`) rather than any upstream parsing or evaluation framework.

Key differences from the upstream Cigna confectionery implementations:

- **Input model**: Vulnetix provides raw file contents as `input.file_contents` (a map of file path to file text). Rules scan this text directly using regex and string operations.
- **Resource parsing**: Terraform HCL blocks are parsed via a shared regex-based helper library (`data.vulnetix.cigna_tf.helpers`), not through a structured HCL AST.
- **Line numbers**: Finding `start_line` is computed from byte offsets (`helpers.line_of`), providing accurate source locations instead of hardcoded values.
- **No variable resolution**: Rules scan the literal text of `.tf` files. References to Terraform variables, locals, or data sources are not resolved — the rule matches only what is explicitly declared in the source.

## Rules

### AWS (54 rules)

| ID | Name | Severity | Kind |
|----|------|----------|------|
| CIGNA-TF-AWS-ACM-01 | ACM certificates must use DNS validation | medium | iac |
| CIGNA-TF-AWS-APIGW-01 | API Gateway REST APIs must have a base-path mapping | low | iac |
| CIGNA-TF-AWS-APIGW-02 | API Gateway stages must enable access logging | medium | iac |
| CIGNA-TF-AWS-CF-01 | CloudFront viewer TLS minimum must be TLSv1.2 or higher | high | iac |
| CIGNA-TF-AWS-CF-02 | CloudFront viewer protocol must enforce HTTPS | high | iac |
| CIGNA-TF-AWS-CF-03 | CloudFront distributions must configure access logging | medium | iac |
| CIGNA-TF-AWS-CT-01 | CloudTrail trails must not be created in application accounts | low | iac |
| CIGNA-TF-AWS-CT-02 | CloudTrail must enable log file validation | medium | iac |
| CIGNA-TF-AWS-DDB-01 | DynamoDB tables must enable server-side encryption | high | iac |
| CIGNA-TF-AWS-EBS-01 | EBS volumes must be encrypted at rest | high | iac |
| CIGNA-TF-AWS-EC2-01 | EC2 instances must have an IAM instance profile | low | iac |
| CIGNA-TF-AWS-EKS-01 | EKS clusters must enable control plane logging | medium | iac |
| CIGNA-TF-AWS-EKS-02 | EKS clusters must use private endpoints | high | iac |
| CIGNA-TF-AWS-EKS-03 | EKS clusters must run Kubernetes 1.15 or newer | medium | iac |
| CIGNA-TF-AWS-EC-01 | ElastiCache replication groups must enable encryption at rest and in transit | high | iac |
| CIGNA-TF-AWS-ES-01 | Elasticsearch domains must deploy into a VPC | high | iac |
| CIGNA-TF-AWS-IAM-01 | IAM policies must not grant full administrative permissions | high | iac |
| CIGNA-TF-AWS-IAM-02 | IAM policies must not use NotAction | medium | iac |
| CIGNA-TF-AWS-IAM-03 | IAM policy attachments must not use overly permissive AWS managed policies | high | iac |
| CIGNA-TF-AWS-IAM-04 | aws_iam_policy_document must not grant wildcard principals | high | iac |
| CIGNA-TF-AWS-IAM-05 | IAM policies must list service actions, not service:* wildcards | medium | iac |
| CIGNA-TF-AWS-IAM-06 | Sensitive IAM actions must be scoped to specific resources | high | iac |
| CIGNA-TF-AWS-IAM-07 | IAM users must not be declared in Terraform | medium | iac |
| CIGNA-TF-AWS-KIN-01 | Kinesis streams must be encrypted with a customer-managed KMS key | medium | iac |
| CIGNA-TF-AWS-KMS-01 | KMS keys must have rotation enabled | medium | iac |
| CIGNA-TF-AWS-LAMBDA-01 | Lambda functions must not reference a role that grants lambda:InvokeFunction | medium | iac |
| CIGNA-TF-AWS-ELB-01 | Application load balancers must enable access logs | medium | iac |
| CIGNA-TF-AWS-ELB-02 | ALB listeners must use HTTPS with a recommended SSL policy | high | iac |
| CIGNA-TF-AWS-ELB-03 | Classic ELB policies must not enable deprecated SSL/TLS protocols | high | iac |
| CIGNA-TF-AWS-ELB-04 | Classic ELBs must have TLS (HTTPS listener + certificate) enabled | high | iac |
| CIGNA-TF-AWS-RDS-01 | RDS DB instances must enable auto minor version upgrades | low | iac |
| CIGNA-TF-AWS-RDS-02 | RDS instances and clusters must encrypt storage with a KMS CMK | high | iac |
| CIGNA-TF-AWS-RDS-03 | RDS DB instances must enable Multi-AZ | medium | iac |
| CIGNA-TF-AWS-RDS-04 | RDS instances must not be publicly accessible | high | iac |
| CIGNA-TF-AWS-RDS-05 | RDS backup_retention_period must be at least 7 days | low | iac |
| CIGNA-TF-AWS-RS-01 | Redshift clusters must be encrypted at rest | high | iac |
| CIGNA-TF-AWS-RS-02 | Redshift clusters must enable audit logging | medium | iac |
| CIGNA-TF-AWS-RS-03 | Redshift clusters must not be publicly accessible | high | iac |
| CIGNA-TF-AWS-RS-04 | Redshift parameter groups must enforce SSL | high | iac |
| CIGNA-TF-AWS-S3-01 | S3 buckets must configure server-side encryption with AES256 or aws:kms | high | iac |
| CIGNA-TF-AWS-S3-02 | S3 bucket ACLs must not be public or authenticated-read | high | iac |
| CIGNA-TF-AWS-S3-03 | S3 bucket policies must not grant wildcard principals without conditions | high | iac |
| CIGNA-TF-AWS-SM-01 | SageMaker endpoints must be encrypted with a KMS key | high | iac |
| CIGNA-TF-AWS-SM-02 | SageMaker notebook instances must be encrypted with a KMS key | high | iac |
| CIGNA-TF-AWS-SM-03 | SageMaker notebook instances must disable direct internet access | high | iac |
| CIGNA-TF-AWS-SG-01 | Security group ingress from 0.0.0.0/0 must be limited to port 80 or 443 | high | iac |
| CIGNA-TF-AWS-SG-02 | Security groups must not allow all ports | high | iac |
| CIGNA-TF-AWS-SNS-01 | SNS topics must configure server-side encryption | medium | iac |
| CIGNA-TF-AWS-SNS-02 | SNS topic policies must not grant wildcard Principal without Condition | high | iac |
| CIGNA-TF-AWS-SQS-01 | SQS queue policies must not grant wildcard Principal without Condition | high | iac |
| CIGNA-TF-AWS-SQS-02 | SQS queues must enable server-side encryption | medium | iac |
| CIGNA-TF-AWS-VPC-01 | VPCs must have an associated flow log | medium | iac |
| CIGNA-TF-AWS-VPC-02 | Internet Gateways must not be created | medium | iac |
| CIGNA-TF-AWS-VPC-03 | VPC Peering Connections must not be created | medium | iac |

### Azure (34 rules)

| ID | Name | Severity | Kind |
|----|------|----------|------|
| CIGNA-TF-AZ-AGW-01 | Application Gateway must have an attached WAF policy | medium | iac |
| CIGNA-TF-AZ-COG-01 | Cognitive Services must be encrypted with a customer-managed key | medium | iac |
| CIGNA-TF-AZ-COG-02 | Cognitive Services must disable local authentication | medium | iac |
| CIGNA-TF-AZ-COG-03 | Cognitive Services must disable public network access | medium | iac |
| CIGNA-TF-AZ-COG-04 | Cognitive Services must set network_acls default_action = Deny | medium | iac |
| CIGNA-TF-AZ-COSMOS-01 | Cosmos DB must disable public network access | medium | iac |
| CIGNA-TF-AZ-DB-01 | MariaDB servers must enable geo-redundant backups | low | iac |
| CIGNA-TF-AZ-DB-02 | MySQL servers must enable geo-redundant backups | low | iac |
| CIGNA-TF-AZ-DB-03 | PostgreSQL servers must enable geo-redundant backups | low | iac |
| CIGNA-TF-AZ-DB-04 | SQL servers must be part of a geo-redundant failover group | low | iac |
| CIGNA-TF-AZ-DBX-01 | Databricks premium workspaces must enable customer-managed key encryption | medium | iac |
| CIGNA-TF-AZ-FD-01 | Front Door must require HTTPS or redirect HTTP to HTTPS | high | iac |
| CIGNA-TF-AZ-FD-02 | Front Door frontend endpoints must attach a WAF policy | medium | iac |
| CIGNA-TF-AZ-FA-01 | Function Apps must require HTTPS | high | iac |
| CIGNA-TF-AZ-FA-02 | Function Apps must use TLS 1.2 or higher | high | iac |
| CIGNA-TF-AZ-KV-01 | Key Vaults must enable purge protection | medium | iac |
| CIGNA-TF-AZ-KV-02 | Key Vaults must enable RBAC authorization | medium | iac |
| CIGNA-TF-AZ-KV-03 | Key Vaults must restrict network access | medium | iac |
| CIGNA-TF-AZ-LA-01 | Log Analytics Workspaces must disable internet queries | medium | iac |
| CIGNA-TF-AZ-LOGIC-01 | Logic Apps must require HTTPS | high | iac |
| CIGNA-TF-AZ-LOGIC-02 | Logic Apps must use TLS 1.2 or higher | high | iac |
| CIGNA-TF-AZ-NAT-01 | NAT Gateways must not be created | medium | iac |
| CIGNA-TF-AZ-PIP-01 | Public IPs must not be created | medium | iac |
| CIGNA-TF-AZ-REDIS-01 | Redis Cache must disable the non-SSL port | high | iac |
| CIGNA-TF-AZ-REDIS-02 | Redis Cache must disable public network access | medium | iac |
| CIGNA-TF-AZ-REDIS-03 | Redis Cache must use TLS 1.2 or higher | high | iac |
| CIGNA-TF-AZ-SA-01 | Storage accounts must disable public blob access | high | iac |
| CIGNA-TF-AZ-SA-02 | Storage accounts must enable HTTPS traffic only | high | iac |
| CIGNA-TF-AZ-SA-03 | Storage accounts must not explicitly allow public blob access | high | iac |
| CIGNA-TF-AZ-SA-04 | Storage accounts must require TLS 1.2 | high | iac |
| CIGNA-TF-AZ-VM-01 | VMs must enable automatic updates | medium | iac |
| CIGNA-TF-AZ-VM-02 | VMs must use an approved SKU (size) | low | iac |
| CIGNA-TF-AZ-WA-01 | Web Apps must require HTTPS | high | iac |
| CIGNA-TF-AZ-WA-02 | Web Apps must use TLS 1.2 or higher | high | iac |

## Structure

```
opa-cigna-tf/
├── rules/
│   ├── _lib/
│   │   └── tf.rego                    # shared helper functions
│   └── terraform/
│       ├── aws/                        # 54 AWS rules
│       │   ├── acm/
│       │   ├── api-gw/
│       │   ├── cloudfront/
│       │   ├── cloudtrail/
│       │   ├── dynamodb/
│       │   ├── ebs/
│       │   ├── ec2/
│       │   ├── eks/
│       │   ├── elasticache/
│       │   ├── elasticsearch/
│       │   ├── iam/
│       │   ├── kinesis/
│       │   ├── kms/
│       │   ├── lambda/
│       │   ├── load-balancer/
│       │   ├── rds/
│       │   ├── redshift/
│       │   ├── s3/
│       │   ├── sagemaker/
│       │   ├── security-group/
│       │   ├── sns/
│       │   ├── sqs/
│       │   └── vpc/
│       └── azure/                      # 34 Azure rules
│           ├── app-gateway/
│           ├── cognitive-services/
│           ├── cosmos-db/
│           ├── database/
│           ├── databricks/
│           ├── front-door/
│           ├── functionapp/
│           ├── key-vault/
│           ├── log-analytics/
│           ├── logic-app/
│           ├── nat-gateway/
│           ├── public-ip/
│           ├── redis-cache/
│           ├── storage-account/
│           ├── virtual-machine/
│           └── web-app/
├── LICENSE
└── README.md
```

All `.rego` files live under `rules/` so the Vulnetix CLI can discover and load them automatically.

## Usage

```bash
# Use alongside built-in rules
vulnetix scan --rule Vulnetix/opa-cigna-tf

# Use only these custom rules (no built-ins)
vulnetix scan --rule Vulnetix/opa-cigna-tf --disable-default-rules
```

## Limitations

- **No variable resolution**: Rules scan literal `.tf` text. Values assigned via Terraform variables, locals, or data sources are not resolved.
- **Name-based cross-resource joins**: Related resources (e.g. `aws_vpc` + `aws_flow_log`) are linked by matching resource name references, not through a dependency graph.
- **IAM policy heuristics**: JSON policy documents embedded in HCL strings are parsed with regex, not a JSON AST. Complex interpolation or conditional logic may not be fully captured.
- **Best-effort text scanning**: The regex-based approach is a best-effort scan of HCL source. It may produce false negatives for unconventional formatting and false positives for commented-out blocks.

## License

Apache License 2.0. Original rule intent from [cigna/confectionery](https://github.com/cigna/confectionery) (also Apache 2.0).
