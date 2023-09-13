# AWS IAM Identity Center - List Permission Sets and Associated User Permissions

AWS IAM Identity Center - List Permission Sets and Associated User Permissions 

## Requirements

* Set the AWS credentials in your terminal.
 * In your AWS login page, select a role with access to AWS IAM Identity Center
 * Select Command line or programmatic access
 * Set AWS environment variables - e.g. copy code in Option 1 in to your terminal
* Python 3
* AWS CLI


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
