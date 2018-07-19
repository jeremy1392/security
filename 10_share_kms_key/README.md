# Share KMS Key with all AWS organization accounts

## Pre-requisites

You must have installed :
- [Python 2.7](https://www.python.org/)
- [Boto3 1.4](https://github.com/boto/boto3)

## Variables (in the script)

- aws_region
    - AWS Region
    - value : environment variable AWS_REGION
- master_account_id 
    - Id of the AWS master account for the AWS Region 
    - value : 548311111111 (AWS_REGION = eu-west-1)
- master_key_alias 
    - Alias of the principal KMS Key in AWS master account 
    - value : ProductionCMK1 (Master Account = 548311111111 and AWS_REGION = eu-west-1)

## Utilization

- Source AWS credentials with full-admin permissions in the master account
- Run the script : `python share_key.py`

# Ouput 

When it's worked, the script prints the following line :
- Put this policy {policy value} on the key {key alias value}
