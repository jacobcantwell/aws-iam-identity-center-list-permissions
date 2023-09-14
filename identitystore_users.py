import boto3
import csv

client = boto3.client('identitystore')
sso_admin_client = boto3.client('sso-admin')

# get policies
def getPolicies(instanceArn, permission_set):
    # list_managed_policies_in_permission_set
    list_managed_policies_in_permission_set = sso_admin_client.list_managed_policies_in_permission_set(
        InstanceArn=instanceArn,
        PermissionSetArn=permission_set
    )["AttachedManagedPolicies"]
    # print(f"list_managed_policies_in_permission_set: {list_managed_policies_in_permission_set}")
    list_managed_policies = "|".join([name["Name"] for name in list_managed_policies_in_permission_set])
    if not list_managed_policies:
        list_managed_policies = "NoManagedPolicy"
    print(f"list_managed_policies: {list_managed_policies}")

    # list_customer_managed_policy_references_in_permission_set
    list_customer_managed_policy_references_in_permission_set = sso_admin_client.list_customer_managed_policy_references_in_permission_set(
        InstanceArn=instanceArn,
        PermissionSetArn=permission_set
    )["CustomerManagedPolicyReferences"]
    # print(f"list_customer_managed_policy_references_in_permission_set: {list_customer_managed_policy_references_in_permission_set}")
    list_customer_managed_policy_references = "|".join([name["Name"] for name in list_customer_managed_policy_references_in_permission_set])
    if not list_customer_managed_policy_references:
        list_customer_managed_policy_references = "NoCustomerPolicy"
    print(f"list_customer_managed_policy_references: {list_customer_managed_policy_references}")

    # get inline policy for this permission set
    inline_policy_for_permission_set = sso_admin_client.get_inline_policy_for_permission_set(
        InstanceArn=instanceArn,
        PermissionSetArn=permission_set
    )["InlinePolicy"]
    if not inline_policy_for_permission_set:
        inline_policy_for_permission_set = "NoInlinePolicy"
    print(f"inline_policy_for_permission_set: {inline_policy_for_permission_set}")

    return list_managed_policies, list_customer_managed_policy_references, inline_policy_for_permission_set

# get AWS accounts
def getAccounts(instanceArn, permission_set):
    # get AWS Accounts in this permission set
    list_accounts_for_provisioned_permission_set = sso_admin_client.list_accounts_for_provisioned_permission_set(
        InstanceArn=instanceArn,
        PermissionSetArn=permission_set
    )["AccountIds"]
    print(f"list_accounts_for_provisioned_permission_set: {list_accounts_for_provisioned_permission_set}")
    return list_accounts_for_provisioned_permission_set

# get permission set details
def getPermissionSetDetails(instanceArn, permission_set):
    permission_set_details = sso_admin_client.describe_permission_set(
        InstanceArn=instanceArn,
        PermissionSetArn=permission_set
    )["PermissionSet"]
    # print(f"permission_set_details: {permission_set_details}")
    permission_set_name = permission_set_details["Name"]
    print(f"permission_set_name: {permission_set_name}")
    return permission_set_name

# get user details
def getUserDetails(identityStoreId, userId):
    print(f"userId: {userId}")
    user = client.describe_user(
        IdentityStoreId=identityStoreId,
        UserId=userId
    )
    userName = user["UserName"]
    print(f"userName: {userName}")
    userFamilyName = user["Name"]["FamilyName"]
    print(f"userFamilyName: {userFamilyName}")
    userGivenName = user["Name"]["GivenName"]
    print(f"userGivenName: {userGivenName}")
    displayName = user["DisplayName"]
    print(f"displayName: {displayName}")
    email = user["Emails"][0]["Value"]
    print(f"email: {email}")
    return userName, userFamilyName, userGivenName, displayName, email

# get group memberships
def getGroupMemberShips(identityStoreId, principalId):
    list_group_memberships = client.list_group_memberships(
        IdentityStoreId=identityStoreId,
        GroupId=principalId
    )["GroupMemberships"]
    print(f"list_group_memberships: {list_group_memberships}")
    return list_group_memberships

# get account assignments
def getAccountAssignments(accountId, instanceArn, permission_set):
    list_account_assignments = sso_admin_client.list_account_assignments(
        AccountId=accountId,
        InstanceArn=instanceArn,
        PermissionSetArn=permission_set
    )["AccountAssignments"]
    print(f"list_account_assignments: {list_account_assignments}")
    return list_account_assignments

# get permission sets
def getPermissionSets(instanceArn):
    list_permission_sets = sso_admin_client.list_permission_sets(
        InstanceArn=instanceArn
    )["PermissionSets"]
    return list_permission_sets

# get group memberships for a user
def getGroupMembershipsForMember(identityStoreId, userId):
    group_memberships = client.list_group_memberships_for_member(
        IdentityStoreId=identityStoreId,
        MemberId={
            'UserId': userId
        }
    )["GroupMemberships"]
    return group_memberships

# make a list of users
users = []
# groups
groups = []
# lists the IAM Identity Center instances
list_instances = sso_admin_client.list_instances()["Instances"]

# get identity store
method = "by_sets"
for instance in list_instances:
    identityStoreId = instance["IdentityStoreId"]
    instanceArn = instance["InstanceArn"]
    print(f"identityStoreId: {identityStoreId}")
    # get permissions sets
    list_permission_sets = getPermissionSets(instanceArn)
    # loop through permission sets
    for permission_set in list_permission_sets:
        print(f"permission_set: {permission_set}")
        # get permission set details
        permission_set_name = getPermissionSetDetails(instanceArn, permission_set)
        # get policies for this permission set
        list_managed_policies, list_customer_managed_policy_references, inline_policy_for_permission_set = getPolicies(instanceArn, permission_set)
        # get accounts for permission set
        list_accounts_for_provisioned_permission_set = getAccounts(instanceArn, permission_set)
        # get users and groups in AWS account
        for accountId in list_accounts_for_provisioned_permission_set:
            # list_account_assignments
            list_account_assignments = getAccountAssignments(accountId, instanceArn, permission_set)
            # process principals
            for principal in list_account_assignments:
                principalType = principal["PrincipalType"]
                principalId = principal["PrincipalId"]
                print(f"principalType: {principalType}, principalId: {principalId}")
                # process principals
                if principalType == "GROUP":
                    list_group_memberships = getGroupMemberShips(identityStoreId, principalId)
                    for member in list_group_memberships:
                        groupId = principalId
                        groups.append({
                            "groupId": groupId,
                            "accountId": accountId,
                            "instanceArn": instanceArn,
                            "identityStoreId": identityStoreId,
                            "permission_set": permission_set
                        })
                        userId = member["MemberId"]["UserId"]
                        userName, userFamilyName, userGivenName, displayName, email = getUserDetails(identityStoreId, userId)
                elif principalType == "USER":
                    groupId = "NoGroupId"
                    groups.append({
                        "groupId": groupId,
                        "accountId": accountId,
                        "instanceArn": instanceArn,
                        "identityStoreId": identityStoreId,
                        "permission_set": permission_set
                    })
                    userId = principalId
                    userName, userFamilyName, userGivenName, displayName, email = getUserDetails(identityStoreId, userId)
                users.append([method, userId, userName, userFamilyName, userGivenName, displayName, email, groupId, accountId, identityStoreId, permission_set_name, list_managed_policies, list_customer_managed_policy_references, inline_policy_for_permission_set])

print(f"groups: {groups}")


# get identity store
method = "by_user"
for instance in list_instances:
    identityStoreId = instance["IdentityStoreId"]
    print(f"identityStoreId: {identityStoreId}")
    # get list of users
    list_users = client.list_users(
        IdentityStoreId=identityStoreId
    )
    for user in list_users["Users"]:
        print(f"user: {user}")
        userId = user["UserId"]
        print(f"userId: {userId}")
        userName, userFamilyName, userGivenName, displayName, email = getUserDetails(identityStoreId, userId)
        # write the data
        users.append([method, userId, userName, userFamilyName, userGivenName, displayName, email])

        # get users groups
        group_memberships = getGroupMembershipsForMember(identityStoreId, userId)
        # loop through groups
        for group_membership in group_memberships:
            groupId = group_membership["GroupId"]
            print(f"groupId: {groupId}")
            membershipId = group_membership["MembershipId"]
            print(f"membershipId: {membershipId}")
            # get group details
            for group in groups:
                if group["groupId"] != groupId:
                    continue
                accountId = group["accountId"]
                identityStoreId = group["identityStoreId"]
                # get permission set
                permission_set = group["permission_set"]
                print(f"permission_set: {permission_set}")
                # get permission set details
                permission_set_name = getPermissionSetDetails(instanceArn, permission_set)
                # get policies for this permission set
                list_managed_policies, list_customer_managed_policy_references, inline_policy_for_permission_set = getPolicies(instanceArn, permission_set)
                # write the data
                users.append([method, userId, userName, userFamilyName, userGivenName, displayName, email, groupId, accountId, identityStoreId, permission_set_name, list_managed_policies, list_customer_managed_policy_references, inline_policy_for_permission_set])

# write a csv of permission sets
header = ['Method', 'UserId', 'UserName', 'FamilyName', 'GivenName', 'DisplayName', 'Email', 'GroupId', 'AWSAccountId', 'IdentityStoreId', 'PermissionSetName', 'AttachedManagedPolicies', 'CustomerManagedPolicyReferences', 'InlinePolicy']
with open('list_permissions.csv', 'w') as f:
    # create the csv writer
    writer = csv.writer(f)
    # write the header
    writer.writerow(header)
    for user in users:
        # write the data
        writer.writerow(user)
