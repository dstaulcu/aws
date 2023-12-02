import json
import urllib.parse
import requests
import boto3
from botocore.exceptions import ClientError
import os
from datetime import datetime

def get_secret(secret_name, region_name):

    # Create a Secrets Manager client
    session = boto3.session.Session()
    client = session.client(
        service_name='secretsmanager',
        region_name=region_name
    )

    try:
        get_secret_value_response = client.get_secret_value(
            SecretId=secret_name
        )
    except ClientError as e:
        # For a list of exceptions thrown, see
        # https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_GetSecretValue.html
        raise e

    # Decrypts secret using the associated KMS key.
    secret = get_secret_value_response['SecretString']
    
    return json.loads(secret)

def lambda_handler(event, context):

    # verify we can access ca_certs file in trust_stores layer
    ca_certs = '/opt/trust_stores/readme.md'
    if not os.path.isfile(ca_certs):
        print('ERROR - Path to ca_certs file "{}" not found. Exiting.'.format(ca_certs))
        exit(1)

        
    # get splunk hec token secret value from aws secrets service
    secret = get_secret(secret_name='splunk_hec_token', region_name='us-east-1')
    splunk_hec_token = secret['splunk_hec_token']
    
    # construct uri and header for post
    splunk_uri = 'https://splunk_host:8088/services/collector/event'    
    headers = {'Authorization': 'Splunk '+ splunk_hec_token}    
    
    # check event structure to derive trigger type for function 
    if not 'Records' in event:
        
        # contruct print statement from event received from lambda test trigger
        my_event = json.dumps(event, indent=None)
        print('lambda test trigger event: {}'.format(my_event))

        
    else:
        
        # construct event for splunk from event received from s3 trigger. 
        # note: despite Records being iterable only 1 member is expected
    
        my_event = {
            'eventTime':event['Records'][0]['eventTime'],
            'eventSource':event['Records'][0]['eventSource'],
            'eventName':event['Records'][0]['eventName'],
            'sourceIPAddress':event['Records'][0]['requestParameters']['sourceIPAddress'],
            'bucket_name':event['Records'][0]['s3']['bucket']['name'],
            'object_key':event['Records'][0]['s3']['object']['key'],
            'object_size':event['Records'][0]['s3']['object']['size'],
            'object_eTag':event['Records'][0]['s3']['object']['eTag']
        }
        
        # convert eventTime from string to datetime and then epoch for use in Splunk _time field
        eventTime_utc = datetime.strptime(my_event['eventTime'], "%Y-%m-%dT%H:%M:%S.%fZ")
        eventTime_epoch = (eventTime_utc - datetime(1970, 1, 1)).total_seconds()
        
        # construct required splunk metadata to post with event
        payload = {
            'index':'tbd', 
            '_time': eventTime_epoch,
#            'host': tbd,
            'source':'tbd', 
            'sourcetype':'tbd'
        }
        
        # update payload with derived event
        payload.update({'event': my_event})
        
        # print('DEBUG - payload: {}'.format(payload))
        
        # post the event to splunk http event collector endpoint
        try:
            r = requests.post(splunk_uri, data=json.dumps(payload), headers=headers, verify=ca_certs)
            r.raise_for_status()
        except requests.exceptions.HTTPError as err:
            raise SystemExit(err)


    
    

