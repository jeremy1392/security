import boto3
import json
import os
import argparse
import sys
import json_delta
import list_account_ids
    
def get_kms_key_policy(master_account_id, account_id_list):
    account_arn_list = ["arn:aws:iam::{0}:root".format(account_id) for account_id in account_id_list]
    return json.dumps({
        "Version": "2012-10-17",
        "Id": "key-default-1",
        "Statement": [
            {
                "Sid": "Enable IAM User Permissions",
                "Effect": "Allow",
                "Principal": {
                    "AWS": "arn:aws:iam::{0}:root".format(master_account_id)
                },
                "Action": "kms:*",
                "Resource": "*"
            },
            {
                "Sid": "Disable CMK deletion",
                "Effect": "Deny",
                "Principal": {
                    "AWS": "*"
                },
                "Action": [
                    "kms:DeleteImportedKeyMaterial",
                    "kms:DeleteAlias",
                    "kms:DisableKey",
                    "kms:ScheduleKeyDeletion"
                ],
                "Resource": "*"
            },
            {
                "Sid": "Enable organizations accounts access to the key",
                "Effect": "Allow",
                "Principal": {
                    "AWS": account_arn_list
                },
                "Action": [
                    "kms:Encrypt",
                    "kms:Decrypt",
                    "kms:DescribeKey",
                    "kms:GenerateDataKey*",
                    "kms:ReEncrypt*"
                ],
                "Resource": "*"
            },
            {
                "Sid": "Allow organizations accounts to attach persistent resources",
                "Effect": "Allow",
                "Principal": {
                    "AWS": account_arn_list
                },
                "Action": [
                    "kms:CreateGrant",
                    "kms:ListGrants",
                    "kms:RevokeGrant"
                ],
                "Resource": "*",
                "Condition": {
                    "Bool": {
                        "kms:GrantIsForAWSResource": "true"
                    }
                }
            }
        ]
    })

def get_master_key_arn(aws_region, master_account_id, master_key_alias, kms_client):
    key_alias_arn = "arn:aws:kms:{0}:{1}:alias/{2}".format(aws_region, master_account_id, master_key_alias)

    key = kms_client.describe_key(
        KeyId=key_alias_arn,
    )

    key_arn = key['KeyMetadata']['Arn']

    return key_arn

def get_key_policy(key_arn, kms_client):
    actual_key_policy = kms_client.get_key_policy(
        KeyId=key_arn,
        PolicyName='default',
    )
    return actual_key_policy['Policy']

def put_new_policy_to_key(key_arn, new_key_policy, kms_client):
    kms_client.put_key_policy(
        KeyId=key_arn,
        PolicyName='default',
        Policy=new_key_policy,
        BypassPolicyLockoutSafetyCheck=False
    )

def print_json_diff(json_source, json_dest):
    diff_lines = json_delta.udiff(json_source, json_dest)
    for line in diff_lines:
        print line
    return diff_lines

def is_policy_diff(master_key_arn, new_key_policy, verbose, kms_client):
    actual_master_key_policy = get_key_policy(master_key_arn, kms_client)
    actual_master_key_policy_sorted = sort_account_list_in_policy(actual_master_key_policy)
    new_key_policy_sorted = sort_account_list_in_policy(new_key_policy)
    if actual_master_key_policy_sorted != new_key_policy_sorted:
        if verbose:
            print_json_diff(actual_master_key_policy_sorted, new_key_policy_sorted)
        return True
    return False

def sort_account_list_in_policy(key_policy_str):
    key_policy = json.loads(key_policy_str)
    for key_policy_statement in key_policy['Statement']:
        aws_account_list = key_policy_statement['Principal']['AWS']
        if isinstance(aws_account_list, list):
            aws_account_list.sort()
    return key_policy

if __name__ == '__main__':
    master_account_id = "548303330441"
    master_key_alias = "ProductionCMK1"
    aws_region = os.environ["AWS_REGION"]

    parser = argparse.ArgumentParser()
    parser.add_argument('-n', '--noop', dest='dry_run', action='store_true')
    parser.add_argument('-v', '--verbose', dest='verbose', action='store_true')
    args = parser.parse_args()

    kms_client = boto3.client('kms')

    master_key_arn = get_master_key_arn(aws_region, master_account_id, master_key_alias, kms_client)
    account_id_list = list_account_ids.get_organizations_account_ids()
    new_key_policy = get_kms_key_policy(master_account_id, account_id_list)

    if args.dry_run:
        print "Dry Run - print the diff between the new and old policy."
        if is_policy_diff(master_key_arn, new_key_policy, args.verbose, kms_client):
            print "Difference with the actual policy detected"
            sys.exit(1)
        else:
            print "No difference detected"
            sys.exit(0)
    else:
        print "Put this policy {0} on the master key {1}.".format(new_key_policy, master_key_alias)
        put_new_policy_to_key(master_key_arn, new_key_policy, kms_client)
        sys.exit(0)
