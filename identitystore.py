import json
import boto3
import botocore
from datetime import date
import csv

AWS_REGION = "ap-southeast-2"

today = date.today()
curr_date = today.strftime("%Y-%m-%d")

iam = boto3.client('iam')

iam_permissions_table = []
user_list_table = []

sso = boto3.client('sso-admin', region_name=AWS_REGION)
identitystore = boto3.client('identitystore', region_name=AWS_REGION)

# lists the IAM Identity Center instances
list_instances = sso.list_instances()["Instances"][0]
print(f"list_instances {list_instances}")

IDENTITY_STORE_ID = list_instances["IdentityStoreId"]
INSTANCE_ARN = list_instances["InstanceArn"]

permission_sets_response = sso.list_permission_sets(
    InstanceArn=INSTANCE_ARN
)
print(permission_sets_response)

# loop through permission set to get list of group ID (to get sso group and users), policies, default versions (for json details)
for item in permission_sets_response.get('PermissionSets'):
    # get list of accounts associated with permission set
    assoc_acc_response = sso.list_accounts_for_provisioned_permission_set(
        InstanceArn=INSTANCE_ARN,
        PermissionSetArn=item
        )
    
    describe_permission_set_response = sso.describe_permission_set(
        InstanceArn=INSTANCE_ARN,
        PermissionSetArn=item
        )

    # Define array to store Principal ID, Account ID and Principal Type
    principal_id_list=[]
    account_list=[]
    principal_type_list=[]
    
    for account in assoc_acc_response.get('AccountIds'):
        # get the principal ID to link with the AWS IAM Identity Center group to get members
        account_assignments_response = sso.list_account_assignments(
            InstanceArn=INSTANCE_ARN,
            AccountId=account,
            PermissionSetArn=item
            )

        for group in account_assignments_response['AccountAssignments']:
            # build json
            principal_id_list.append(group['PrincipalId'])
            account_list.append(group['AccountId'])
            principal_type_list.append(group['PrincipalType'])
            
    # get the list of managed policies attached in each of the permission set
    managed_policies_response = sso.list_managed_policies_in_permission_set(
        InstanceArn=INSTANCE_ARN,
        PermissionSetArn=item
        )
            
    managed_policies = []
    # loop through each policy arn to get version ID in order to list out json
    for i in managed_policies_response['AttachedManagedPolicies']:
        policy_details = iam.get_policy(
            PolicyArn=i['Arn']
            )
        defaultVersionId = policy_details['Policy']['DefaultVersionId']
        policy_json = iam.get_policy_version(
            PolicyArn=i['Arn'],
            VersionId=defaultVersionId
            )
        managed_policies.append({'policryArn': i['Arn'], 'policy_type': 'aws_managed', 'policyJson': json.dumps(policy_json['PolicyVersion']['Document'], default=str)})
    
    # get the inline policy attached in each of the permission set
    inline_policies_response = sso.get_inline_policy_for_permission_set(
        InstanceArn=INSTANCE_ARN,
        PermissionSetArn=item
        )

    # get the list of customer managed policy references attached in each of the permission set
    customer_policies_response = sso.list_customer_managed_policy_references_in_permission_set(
        InstanceArn=INSTANCE_ARN,
        PermissionSetArn=item
        )
    # print(customer_policies_response)

    # get the permission boundary attached in each of the permission set
    try: 
        permissions_boundary_response = sso.get_permissions_boundary_for_permission_set(
            InstanceArn=INSTANCE_ARN,
            PermissionSetArn=item
            )
    except botocore.exceptions.ClientError as error:
        if error.response['Error']['Code'] == 'ResourceNotFoundException':
            print('No Permission Boundary attached')
            permissions_boundary_response = {'PermissionsBoundary':''}
        else:
            raise error

    # store all in ddb table
    iam_permissions_table.append({
            'id': INSTANCE_ARN,
            'permissionSetArn': item,
            'permissionSetName': describe_permission_set_response['PermissionSet']['Name'],
            'principalId': principal_id_list,
            'accountId': account_list,
            'principalType': principal_type_list,
            'managedPolicies': managed_policies,
            'inlinePolicies': inline_policies_response['InlinePolicy'],
            'customerPolicies': customer_policies_response['CustomerManagedPolicyReferences'],
            'permissionsBoundary': permissions_boundary_response['PermissionsBoundary']
        })

# Get list of users in Identity Store
user_list_response = identitystore.list_users(
    IdentityStoreId=IDENTITY_STORE_ID
)

user_list = user_list_response.get('Users')

# if total number of users exceed the size of one page
while 'NextToken' in user_list_response:
    user_list_response = identitystore.list_users(
    IdentityStoreId=IDENTITY_STORE_ID,
    NextToken=user_list_response['NextToken']
    )
    # Store paginated results into a list
    for user in user_list_response.get('Users'):
        user_list.append(user)


# loop through user lists to get the membership details (user Id, group ID in GroupMemberships details, user names etc)
for user in user_list:
    # get member group (groupId) details
    user_group_membership_response = identitystore.list_group_memberships_for_member(
        IdentityStoreId=IDENTITY_STORE_ID,
        MemberId={
            'UserId': user['UserId']
        }
    )
    group_name_list=[]
    for group in user_group_membership_response['GroupMemberships']:
        group_description_response = identitystore.describe_group(
            IdentityStoreId=IDENTITY_STORE_ID,
            GroupId=group['GroupId']
            )
        group_name_list.append(group_description_response['DisplayName'])
    
    # store all in ddb table
    user_list_table.append({
            'userId': user['UserId'],
            'userName': user['UserName'],
            'groupMemberships': user_group_membership_response['GroupMemberships'],
            'groupName': group_name_list
        })



def query_ddb_to_populate_report(user_name, principal_id, group_name, principal_type, iam_permissions_table, instance_arn, writer):
    permission_response = iam_permissions_table
    print('query result for user:' + user_name + ', group name:'+ group_name)
    # print(permission_response)

    if len(permission_response) == 0:
        writer.writerow([user_name, principal_id, principal_type, group_name, 'not_assigned'])
    else:
        for permission in permission_response:
            print('Permissions for user:' + user_name + ', group name:'+ group_name)
            # print(permission)
            
            # Excel has a 32,767 char limit, check if each policy exceeds the limit
            policy_type_list = ['inlinePolicies', 'customerPolicies','managedPolicies' ]
            for policy_type in policy_type_list:
                if len(str(permission[policy_type])) > 32700:
                    permission[policy_type] = 'Exceed character limit for excel, refer to AWS Console for full policy details'
                
            # Loop through all assignments of a permission set for individual users and groups
            for no_of_assignments, accountid in enumerate(permission['accountId']):
                # Additional principal type check to prevent duplicated records (a user can be assigned individually or assigned as part of a group)
                if principal_type == permission['principalType'][no_of_assignments]:
                    writer.writerow([user_name, principal_id, permission['principalType'][no_of_assignments], group_name, permission['accountId'][no_of_assignments], permission['permissionSetArn'], permission['permissionSetName'], permission['inlinePolicies'], permission['customerPolicies'], permission['managedPolicies'], permission['permissionsBoundary']])
                    
            
user_list_response = user_list_table

with open('results-' + curr_date + '.csv', 'w') as f:
    writer = csv.writer(f)
    writer.writerow(['User', 'PrincipalId', 'PrincipalType', 'GroupName', 'AccountIdAssignment', 'PermissionSetARN', 'PermissionSetName', 'Inline Policy', 'Customer Managed Policy','AWS Managed Policy', 'Permission Boundary'])
    
    for user in user_list_response:
        print('extracting user data')
        print(user)
        user_id = user['userId']
        user_name = user['userName']
        group_name = ''
    
        # Check individual user assignment first
        query_ddb_to_populate_report(user_name, user_id, group_name, 'USER', iam_permissions_table, INSTANCE_ARN, writer)

        # Check if user is in a group and group assignment 
        if user['groupMemberships']:
            for idx, group in enumerate(user['groupMemberships']):
                group_id = group['GroupId']
                group_name = user['groupName'][idx]
                print('groupname is: ' + group_name)
                query_ddb_to_populate_report(user_name, group_id, group_name, 'GROUP', iam_permissions_table, INSTANCE_ARN, writer)


