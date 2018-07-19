import boto3
import json
import os
import argparse
import sys
import json_delta

def get_organizations_account_ids():
    organizations_client = boto3.client('organizations')
    listOfAccounts = []
    firstAccountList = organizations_client.list_accounts(MaxResults=20)
    for account in filter(lambda x: x["Status"] == "ACTIVE", firstAccountList["Accounts"]):
        listOfAccounts.append(account["Id"])

    if "NextToken" in firstAccountList:
        NextTokenRetrieved = firstAccountList["NextToken"]
        while NextTokenRetrieved:
            accountList = organizations_client.list_accounts(MaxResults=20,NextToken=NextTokenRetrieved)
            for account in filter(lambda x: x["Status"] == "ACTIVE", accountList["Accounts"]):
                listOfAccounts.append(account["Id"])
            NextTokenRetrieved = accountList["NextToken"] if "NextToken" in accountList else None

    return listOfAccounts

#Use it for tests only
if __name__ == '__main__':
    master_account_id = "548303330441"
    master_key_alias = "ProductionCMK1"
    aws_region = os.environ["AWS_REGION"]

    account_id_list = get_organizations_account_ids()
    print account_id_list
    sys.exit(0)
