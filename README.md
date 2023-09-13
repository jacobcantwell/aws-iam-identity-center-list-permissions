# AWS IAM Identity Center - List Permission Sets and Associated User Permissions

This project provides examples and sample code to audit AWS IAM identity store at scale.

With these scripts, you can:
* Query information about users and groups in IAM Identity Center
* Find out which users are members of which groups

## Prerequisites

Before you start you should have the following prerequisites:
* An Organization in AWS Organizations
* Administrative access to the AWS IAM Identity Center
* Python version 3.10.5 or later
* AWS CLI

## Environment Setup

* Clone this repository

```
git clone https://github.com/jacobcantwell/aws-iam-identity-center-list-permissions
```

### Set the AWS credentials in your terminal.
 * In your AWS login page, select a role with access to AWS IAM Identity Center
 * Select Command line or programmatic access
 * Set AWS environment variables - e.g. copy code in Option 1 in to your terminal

## To Run

```
python3 identitystore_users.py
```

## Output CSV

The output CSV includes these headers:

* UserId
* UserName
* FamilyName
* GivenName
* DisplayName
* Email
* AWSAccountId
* IdentityStoreId
* PermissionSetName
* AttachedManagedPolicies (Pipe delimited list)
* CustomerManagedPolicyReferences (Pipe delimited list)
* GroupDisplayName
