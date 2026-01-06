# AWS Certified Security - Specialty (SCS-C03) Exam Notes

**Exam Code:** SCS-C03  
**Passing Score:** 750/1000  
**Format:** Multiple Choice, Multiple Response, Ordering, Matching  
**Version:** Updated late 2025 (Includes GenAI Security & Split Detection/Response domains)

---

## 📚 Table of Contents
1. [Domain 1: Detection (16%)](#domain-1-detection)
2. [Domain 2: Incident Response (14%)](#domain-2-incident-response)
3. [Domain 3: Infrastructure Security (18%)](#domain-3-infrastructure-security)
4. [Domain 4: Identity & Access Management (20%)](#domain-4-identity--access-management)
5. [Domain 5: Data Protection (18%)](#domain-5-data-protection)
6. [Domain 6: Security Foundations & Governance (14%)](#domain-6-security-foundations--governance)
7. [⚡ SCS-C03 New Topics (GenAI/OCSF)](#-scs-c03-new-topics)
8. [📝 Quick Cheat Sheets](#-quick-cheat-sheets)

---

## Domain 1: Detection

### AWS Security Hub
* **Function:** Centralized dashboard for security alerts (findings) and compliance checks.
* **ASFF (AWS Security Finding Format):** Standard format for aggregating findings from GuardDuty, Inspector, Macie, etc.
* **Cross-Region Aggregation:** Must be enabled explicitly to view findings from multiple regions in a single "Master" region.

### Amazon GuardDuty
* **Type:** Threat detection service (Intelligent Detection).
* **Data Sources:** CloudTrail (Management + Data Events), VPC Flow Logs, DNS Logs, EKS Audit Logs.
* **Key Finding Types:**
    * `CryptoCurrency:EC2/BitcoinTool.B` (Mining)
    * `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration` (Instance role creds used outside EC2)
* **Trusted IP Lists:** Prevent false positives from known scanners (white-listing).
* **Threat IP Lists:** Alert on communication with known bad IPs (black-listing).

### Amazon Inspector
* **Function:** Automated vulnerability management.
* **Scanning:**
    * **EC2:** Scans for CVEs and Network Reachability (requires SSM Agent).
    * **ECR:** Scans container images for vulnerabilities upon push or continuous.
    * **Lambda:** Scans function code + layers.
* **Deep Inspection:** Inspector can now scan EC2 paths for vulnerabilities, not just OS packages.

### AWS Config
* **Function:** Resource inventory, configuration history, and compliance auditing.
* **Managed Rules:** Pre-built rules (e.g., `s3-bucket-ssl-requests-only`).
* **Remediation:** Can trigger SSM Automation documents to auto-fix non-compliant resources.
    * *Example:* If a Security Group allows port 22 to 0.0.0.0/0 -> Config triggers SSM to remove the rule.

---

## Domain 2: Incident Response

### Incident Response Lifecycle
1.  **Preparation:** Runbooks, access pre-provisioning.
2.  **Detection & Analysis:** GuardDuty, CloudWatch Alarms.
3.  **Containment:** Isolate EC2 (SG with no rules), Deny IAM policies.
4.  **Eradication:** Delete root cause, patch.
5.  **Recovery:** Restore from backup.
6.  **Post-Incident Activity:** Lessons learned.

### Compromised EC2 Instance (Isolation Steps)
**Order matters:**
1.  **Capture Metadata:** Snapshot the volume (forensics).
2.  **Isolate:** Change Security Group to allow NO inbound/outbound traffic.
    * *Note:* Do **not** stop/terminate immediately if you need memory dump.
3.  **Tag:** Mark as "Compromised" / "Do Not Delete".
4.  **Investigate:** Attach snapshot to a forensic instance in an isolated VPC.

### Compromised IAM Credentials
1.  **Identify:** CloudTrail logs showing strange API calls.
2.  **Contain:**
    * Attach `AWSRevokeOlderSessions` (Deny all actions before current timestamp).
    * Deactivate Access Keys.
    * Change Password.
3.  **Remediate:** Rotate keys, enable MFA.

### AWS Systems Manager (SSM)
* **Runbooks:** Automate incident response actions.
* **Session Manager:** Secure shell access to EC2 without opening port 22/3389 (Audited via CloudTrail/S3).

---

## Domain 3: Infrastructure Security

### Network Edge Defense
* **WAF (Web Application Firewall):**
    * Layer 7 protection (SQL injection, XSS).
    * Attaches to: CloudFront, ALB, API Gateway, AppSync.
    * **Web ACLs:** Rules (Rate-based, Managed Rule Groups).
* **AWS Shield:**
    * **Standard:** Free, L3/L4 DDoS protection.
    * **Advanced:** Paid, L7 protection, access to DRT (DDoS Response Team), Cost Protection (refunds bill spikes from DDoS).
* **Network Firewall:**
    * VPC-level firewall. Supports **Suricata** rules (IPS/IDS), Deep Packet Inspection (DPI), Domain filtering (SNI).

### VPC Security
* **Security Groups (SG):** Stateful (Return traffic allowed automatically). Instance level.
* **NACLs:** Stateless (Must allow return traffic). Subnet level. Good for blocking specific IPs.
* **VPC Endpoints:**
    * **Gateway:** S3 and DynamoDB only. Route table entry needed. Free.
    * **Interface (PrivateLink):** All other services. Uses ENI in subnet. Paid. Keeps traffic on AWS backbone.

### CloudFront Security
* **OAC (Origin Access Control):** Replaces OAI. Best way to restrict S3 access so *only* CloudFront can read files.
* **Geo-restriction:** Whitelist/blacklist countries at the edge.
* **Field-Level Encryption:** Encrypt specific form fields (e.g., credit card) at edge before sending to origin.

---

## Domain 4: Identity & Access Management

### Policy Evaluation Logic (Crucial)
AWS evaluates policies in this order:
1.  **Explicit Deny:** If ANY policy says "Deny", it is a final DENY.
2.  **Organizations SCPs:** Acts as a filter (Limit max permissions).
3.  **Resource-based Policies (e.g., S3 Bucket Policy):** Checked.
4.  **Identity-based Policies (IAM User/Role):** Checked.
5.  **Permissions Boundaries:** Acts as a filter (Limit max permissions).
6.  **Session Policies:** Passed when assuming a role.
7.  **Implicit Deny:** If nothing says "Allow", it is DENIED.

### Cross-Account Access
* **The "Confused Deputy" Problem:**
    * **Solution:** Use `sts:ExternalId` in the Trust Policy when a 3rd party assumes a role in your account.
* **Role Assumption:**
    * Account A (Dev) needs access to Account B (Prod).
    * Account B creates Role with Trust Policy allowing Account A.
    * Account A grants User permission to `sts:AssumeRole`.

### IAM Identity Center (formerly SSO)
* Centralized access for multiple AWS accounts.
* Integrates with Active Directory, Okta, Ping (SAML 2.0).
* **Permission Sets:** Defines what users can do in assigned accounts.

---

## Domain 5: Data Protection

### KMS (Key Management Service)
* **Symmetric (AES-256):** One key for encrypt/decrypt. Used by AWS services (S3, EBS, RDS).
* **Asymmetric (RSA/ECC):** Public (encrypt) / Private (decrypt). Used for signing or use outside AWS.
* **Key Policies:** The *primary* way to control access to a KMS key. IAM policies alone are not enough if the Key Policy doesn't allow IAM.
* **Key Rotation:**
    * **AWS Managed:** Auto-rotates every 1 year (cannot delete).
    * **Customer Managed (CMK):** Optional auto-rotate every 1 year.
    * **Imported Key Material:** NO auto-rotation. You must manually rotate.

### S3 Security
* **Bucket Policy:** Resource-based. Good for "Force SSL", "Deny Upload if unencrypted", "Cross-account access".
* **Object Lock:** WORM (Write Once Read Many).
    * *Governance Mode:* Can be bypassed with special permission.
    * *Compliance Mode:* CANNOT be bypassed (even by root) until retention period ends.
* **Glacier Vault Lock:** Enforce compliance on archives (once locked, policy is immutable).

### Secrets Manager vs Parameter Store
* **Secrets Manager:** Auto-rotation of credentials (RDS, Redshift, DocumentDB). Paid.
* **Systems Manager Parameter Store:** Store strings/passwords. No native auto-rotation (requires custom Lambda). Free (mostly).

### Data Masking
* **Macie:** Discovers sensitive data (PII, Credit Cards) in S3 using ML.
* **CloudWatch Logs Data Protection:** Mask sensitive data (email, SSN) *as it is ingested* into CloudWatch logs.

---

## Domain 6: Security Foundations & Governance

### AWS Organizations
* **SCPs (Service Control Policies):**
    * Apply to OU or Root.
    * **Cannot** grant permissions; only **Restrict** them.
    * *Example:* Deny `ec2:RunInstances` in `us-east-1` region.
    * Root user in member account is affected by SCPs.

### AWS Artifact
* Portal for on-demand access to AWS compliance reports (SOC2, PCI-DSS, ISO).
* Use this when an auditor asks for "AWS's security certification".

---

## ⚡ SCS-C03 New Topics

### Generative AI Security
* **OWASP Top 10 for LLM:** Understand prompt injection, data leakage, and training data poisoning.
* **Bedrock Security:** Use **Guardrails for Amazon Bedrock** to filter harmful content and PII in prompts/responses.
* **Audit:** Log Bedrock API calls via CloudTrail.

### OCSF (Open Cybersecurity Schema Framework)
* Standard open-source schema for security logs.
* **Security Hub** and **Amazon Security Lake** use OCSF to normalize data from various sources (AWS + 3rd party) to make querying easier.

### EKS & Container Security
* **Pod Identity:** New preferred way to give IAM permissions to Pods (replaces IRSA - IAM Roles for Service Accounts).
* **Runtime Security:** GuardDuty now supports EKS Runtime Monitoring.

---

## 📝 Quick Cheat Sheets

### Security Group vs NACL
| Feature | Security Group | NACL |
| :--- | :--- | :--- |
| **Level** | Instance (ENI) | Subnet |
| **State** | Stateful | Stateless |
| **Rules** | Allow Only | Allow & Deny |
| **Order** | All rules evaluated | Number order (lowest first) |
| **Defense** | First line of defense | Second line of defense |

### Encryption Key Types
| Type | Usage | Rotation |
| :--- | :--- | :--- |
| **AWS Owned** | S3 default, Log encryption | Managed by AWS (invisible to you) |
| **AWS Managed** | Created by service (e.g., `aws/s3`) | Auto (1 year), Mandatory |
| **Customer Managed** | Created by you | Optional (1 year), Manual |
| **Imported Material** | You upload bits | **Manual Only** (No auto-rotation) |

### Logging & Monitoring Mapping
* **"Who API'd what?"** -> CloudTrail
* **"What is the network traffic?"** -> VPC Flow Logs
* **"Is my bucket public?"** -> Config / S3 Block Public Access
* **"Is there a vulnerability?"** -> Inspector
* **"Is there an active threat/attack?"** -> GuardDuty
* **"Sensitive Data in S3?"** -> Macie
