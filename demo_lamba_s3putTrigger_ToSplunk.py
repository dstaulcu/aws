import json
import urllib.parse
import requests
import boto3
from botocore.exceptions import ClientError
import os

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

    # get splunk hec token secret value from aws secrets service
    secret = get_secret(secret_name='splunk_hec_token', region_name='us-east-1')
    splunk_hec_token = secret['splunk_hec_token']
    
    # construct uri and header for post
    splunk_uri = 'https://splunk_host:8088/services/collector/event'    
    headers = {'Authorization': 'Splunk '+ splunk_hec_token}    
    
    # construct required splunk metadata to post with event
    payload = {
        'index':'test', 
        'host':'host_tbd', 
        'source':'source_tbd', 
        'sourcetype':'sourcetype_tbd'
    }
    
    # handle varying event structures depending on trigger for function
    if 'Records' in event:
        # derive from s3 event data 
        for record in event['Records']:
            my_event = {
                'eventTime':record['eventTime'],
                'eventSource':record['eventSource'],
                'eventName':record['eventName'],
                'sourceIPAddress':record['requestParameters']['sourceIPAddress'],
                'bucket_name':record['s3']['bucket']['name'],
                'object_key':record['s3']['object']['key'],
                'object_size':record['s3']['object']['size'],
                'object_eTag':record['s3']['object']['eTag']
            }
    else:
        # derive from lambda event data
        my_event = json.dumps(event, indent=None)

    # update payload with derived event
    payload.update({'event': my_event})    
    
    # print('input for event to post to splunk http event collector - splunk_uri: {} and payload: {}'.format(splunk_uri, payload))
    
    # lets see if we can access the readme.md file in the trust_store layer!
    file_path = '/opt/trust_stores/readme.md'
    if os.path.isfile(file_path):
        print('file_path: {} exists!'.format(file_path))
    else:
        print('file_path: {} not found!'.format(file_path))

    
    '''
    r = requests.post(splunk_uri, data=json.dumps(payload), headers=headers, verify=True)
    print("Splunk hec status code: {}, status text: {}".format(r.status_code, r.text))
    '''
