import boto3
import botocore.exceptions
import os
import time

# purpose - receive, process, and delete sqs messages from queue

# create sqs client
try:
    sqs = boto3.client('sqs')
except ClientError as e:
    print("Unexpected error in boto3 client creation: {}".format(e))
    quit()
    
queue_url = 'https://sqs.us-east-2.amazonaws.com/293354421824/MyQueue'   

# Receive message from SQS queue
response = sqs.receive_message(
    QueueUrl = queue_url,
    MaxNumberOfMessages = 10,
    WaitTimeSeconds = 20
)

# check to see if messages key is in response list
if 'Messages' in response:
    # process each message
    for i in range(len(response['Messages'])):
        message = response['Messages'][i]
        print('Item: "{}", MessageId: "{}", Body: "{}"'.format(
            i,
            message['MessageId'], 
            message['Body']
            )
        )
        # delete message after reading
        sqs.delete_message(
            QueueUrl = queue_url,
            ReceiptHandle = message['ReceiptHandle']        
        )
