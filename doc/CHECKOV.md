# Checkov

**Checkov** is an open-source static analysis tool designed to scan infrastructure-as-code (IaC) for security and compliance misconfigurations. When used in conjunction with Terraform, Checkov scans the Terraform configuration files to identify issues before deployment. In the context of Prisma Cloud, Checkov plays a crucial role in static and dynamic analysis, helping to ensure that cloud infrastructure adheres to best security practices and compliance requirements.

## Integration with Prisma Cloud

**Prisma Cloud** offers comprehensive security and compliance monitoring for cloud-native applications and infrastructure. Prisma Cloud integrates with Checkov to provide policy-based security and compliance checks for IaC, including Terraform, CloudFormation, and Kubernetes files. This integration enhances the ability to enforce security controls throughout the CI/CD pipeline, ensuring that infrastructure meets predefined standards before it is deployed to production environments.

## Controls Defined in Checkov

Checkov comes with a vast array of predefined security controls and policies, which are used to assess the Terraform code. These controls cover various domains such as:
- Security misconfigurations
- Compliance violations (e.g., PCI-DSS, HIPAA, SOC 2)
- Best practices for cloud platforms (e.g., AWS, GCP, Azure)

The controls are defined and maintained by the open-source community and security experts at **Bridgecrew** (the creators of Checkov). Prisma Cloud extends these controls by integrating its own policies and rules to align with organizational security standards and regulatory compliance frameworks.

### How Controls are Updated

The security and compliance controls used by Checkov are regularly updated to reflect changes in best practices, cloud service provider configurations, and regulatory requirements. This ensures that organizations using Checkov for Terraform are scanning against the latest security and compliance baselines.

1. **Community Updates**: As an open-source project, Checkov benefits from contributions by the community. New rules and controls are frequently added by contributors, security experts, and cloud architects.
   
2. **Bridgecrew Updates**: Bridgecrew's team continuously works on updating controls to cover newly identified vulnerabilities, changes in cloud provider services, and evolving regulatory requirements. These updates are automatically integrated into Checkov.

3. **Prisma Cloud Updates**: Prisma Cloud continuously updates its policies and controls to reflect the latest compliance requirements and security standards. When Checkov is used as part of Prisma Cloud's pipeline, it benefits from these automatic updates, ensuring that both static and dynamic analysis scans are based on the most current policies.

## Benefits of Using Checkov with Prisma Cloud

- **Early Detection**: Checkov allows security and compliance issues to be caught early in the development lifecycle, minimizing the risk of deploying insecure infrastructure.
- **Automated Compliance**: With regularly updated controls, Checkov helps enforce compliance requirements automatically.
- **Seamless Integration**: Prisma Cloud’s integration with Checkov makes it easy to embed security checks into CI/CD pipelines, improving security without slowing down development.

## Mapping Checkov Controls to AWS SCP

Checkov controls can be aligned with AWS Service Control Policies (SCP) if you define a control that serves the same purpose. AWS SCPs are a feature of AWS Organizations that allow you to control the maximum available permissions for all accounts within an organization. While SCPs enforce guardrails at the IAM level, Checkov operates at the infrastructure-as-code (IaC) level, ensuring that configurations follow security and compliance guidelines before deployment.

### Here’s how the two can map together:

- **Similar Goal**: Both Checkov controls and AWS SCPs aim to enforce security and compliance. AWS SCPs control what actions an account or user can perform at a high level, whereas Checkov checks whether your Terraform code is configured according to best practices and policies.

- **Custom Controls**: If your organization has specific AWS SCPs (such as denying certain actions or services across accounts), you can create custom Checkov policies that mirror the logic of the SCP. For example, if your SCP denies access to certain EC2 instance types for cost control, you can define a Checkov policy that prevents these types from being defined in Terraform code.

- **Preventive Approach**: Checkov helps to prevent violations at the development phase. By defining a Checkov control that checks the same rules as an SCP, you ensure that these configurations are flagged before they ever reach production, creating an extra layer of preventive enforcement.
