import zlib
import base64
import json
import boto3
import datetime
import os
import time
import yaml
import string
import StringIO
import re
from pprint import pprint
from email.header import Header
from email.message import Message
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.utils import make_msgid
from email.utils import formatdate

def AlertCST(no_compliant_bucket, emailTo, emailFrom):
    ses = boto3.client('ses')
    for v in no_compliant_bucket:
      msg = MIMEMultipart()
      msg['Subject'] = "[Critical Alert AWS]"
      msg['From'] = emailFrom
      msg['To'] = ", ".join(emailTo)
      msg['Message-Id'] = make_msgid()
      msg.preamble = 'Multipart message. \n'
      part = MIMEText(v)
      msg.attach(part)

      result = ses.send_raw_email(
            Source=msg['From'],
            Destinations=emailTo,
            RawMessage={
                   'Data': msg.as_string(),
                }
            )

def lambda_handler(event, context):
  stream = open('config.yaml', 'r')
  config = yaml.load(stream)
  emailTo = []
  emailTo.append(config['TO_EMAIL'])
  emailFrom = config['FROM_EMAIL']

  list_bucket = []
  no_compliant_bucket = []
  no_compliant_bucket_nb = 0

  print "[Starting s3 checker]"
  print ""

  account = boto3.client('sts').get_caller_identity().get('Account')
  s3 = boto3.client('s3')

  #Loop to get all s3 buckets
  #checking if a bucket is public

  list_bucket = s3.list_buckets()
  v=0
  for i in list_bucket['Buckets']:
    print(i['Name'])
    for n in i:
      acl = s3.get_bucket_acl(Bucket=i['Name'])
      perm = acl['Grants']
      for c in perm:
        if ( c['Grantee']['Type'] == "Group" ):
          v=v+1
          try:
            type = c['Grantee']['URI']
          except KeyError:
            pass
          if (type == "http://acs.amazonaws.com/groups/global/AllUsers") and (v < 2):
            no_compliant_bucket_nb = no_compliant_bucket_nb+1
            no_compliant_bucket.append("[CRTICAL ALERT] Possible data leaks for the bucket: " + i['Name'] + " which is PUBLIC into account: " + account + " !\n Please Investigate now ! ")
            break

  AlertCST(no_compliant_bucket, emailTo, emailFrom)
