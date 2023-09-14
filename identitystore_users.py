import boto3
import csv

client = boto3.client('identitystore')
sso_admin_client = boto3.client('sso-admin')

# write a csv of permission sets
header = ['UserId', 'UserName', 'FamilyName', 'GivenName', 'DisplayName', 'Email', 'AWSAccountId', 'IdentityStoreId', 'PermissionSetName', 'AttachedManagedPolicies', 'CustomerManagedPolicyReferences']
with open('list_permissions.csv', 'w') as f:
    # create the csv writer
    writer = csv.writer(f)
    # write the header
    writer.writerow(header)

    # lists the IAM Identity Center instances
    list_instances = sso_admin_client.list_instances()["Instances"]

    # get identity store
    for instance in list_instances:
        identityStoreId = instance["IdentityStoreId"]
        instanceArn = instance["InstanceArn"]
        print(f"identityStoreId: {identityStoreId}")
        # get permissions sets
        list_permission_sets = sso_admin_client.list_permission_sets(
            InstanceArn=instanceArn
        )["PermissionSets"]
        for permission_set in list_permission_sets:
            print(f"permission_set: {permission_set}")
            permission_set_details = sso_admin_client.describe_permission_set(
                InstanceArn=instanceArn,
                PermissionSetArn=permission_set
            )["PermissionSet"]
            # print(f"permission_set_details: {permission_set_details}")
            permission_set_name = permission_set_details["Name"]
            print(f"permission_set_name: {permission_set_name}")

            # list_managed_policies_in_permission_set
            list_managed_policies_in_permission_set = sso_admin_client.list_managed_policies_in_permission_set(
                InstanceArn=instanceArn,
                PermissionSetArn=permission_set
            )["AttachedManagedPolicies"]
            # print(f"list_managed_policies_in_permission_set: {list_managed_policies_in_permission_set}")
            list_managed_policies = "|".join([name["Name"] for name in list_managed_policies_in_permission_set])
            print(f"list_managed_policies: {list_managed_policies}")

            # list_customer_managed_policy_references_in_permission_set
            list_customer_managed_policy_references_in_permission_set = sso_admin_client.list_customer_managed_policy_references_in_permission_set(
                InstanceArn=instanceArn,
                PermissionSetArn=permission_set
            )["CustomerManagedPolicyReferences"]
            # print(f"list_customer_managed_policy_references_in_permission_set: {list_customer_managed_policy_references_in_permission_set}")
            list_customer_managed_policy_references = "|".join([name["Name"] for name in list_customer_managed_policy_references_in_permission_set])
            print(f"list_customer_managed_policy_references: {list_customer_managed_policy_references}")

            # get AWS Accounts in this permission set
            list_accounts_for_provisioned_permission_set = sso_admin_client.list_accounts_for_provisioned_permission_set(
                InstanceArn=instanceArn,
                PermissionSetArn=permission_set
            )["AccountIds"]
            print(f"list_accounts_for_provisioned_permission_set: {list_accounts_for_provisioned_permission_set}")

            # get users and groups in AWS account
            for accountId in list_accounts_for_provisioned_permission_set:
                # list_account_assignments
                list_account_assignments = sso_admin_client.list_account_assignments(
                    AccountId=accountId,
                    InstanceArn=instanceArn,
                    PermissionSetArn=permission_set
                )["AccountAssignments"]
                print(f"list_account_assignments: {list_account_assignments}")

                for principal in list_account_assignments:
                    principalType = principal["PrincipalType"]
                    principalId = principal["PrincipalId"]
                    print(f"principalType: {principalType}, principalId: {principalId}")

                    # process groups
                    if principalType == "GROUP":
                        list_group_memberships = client.list_group_memberships(
                            IdentityStoreId=identityStoreId,
                            GroupId=principalId
                        )["GroupMemberships"]
                        print(f"list_group_memberships: {list_group_memberships}")
                        for member in list_group_memberships:
                            userId = member["MemberId"]["UserId"]
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
                            
                            data = [userId, userName, userFamilyName, userGivenName, displayName, email, accountId, identityStoreId, permission_set_name, list_managed_policies, list_customer_managed_policy_references]
                            # write the data
                            writer.writerow(data)
                    
                    elif principalType == "USER":
                        user = client.describe_user(
                            IdentityStoreId=identityStoreId,
                            UserId=principalId
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
                        
                        data = [principalId, userName, userFamilyName, userGivenName, displayName, email, accountId, identityStoreId, permission_set_name, list_managed_policies, list_customer_managed_policy_references]
                        # write the data
                        writer.writerow(data)
