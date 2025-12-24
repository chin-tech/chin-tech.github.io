---
heroImage: '../../assets/cloud_resume.gif'
layout: post
description: Going through the cloud-resume challenge using AWS
postType: OTHER
pubDate:  2025-07-06
title: "The Cloud Resume"
date: Sun Jul 6 07:54:00 -1000
---

## Overview

I decided to undertake the [Cloud Resume Challenge](https://cloudresumechallenge.dev/docs/the-challenge/aws/). I've deployed a few things to the cloud and made a full bash deployment script for a website that pushes it to Cloudfront and does all the necessary steps. There's a few things I wasn't sure of, which is mainly how lambda works in AWS and implementing a NoSQL database. So not a large gap in my ability, but there is an extra two challenges that seemed perfect and that is Terraforming it and using Websockets and DynamoDB for the counter. Here's a smidge of my thought process, struggles, and surprises. It's not a tutorial by any means, but I think I provide a slightly more specifics than the challenge for AWS. I have a public MVP [here](https://github.com/chin-tech/cloud_resume_project).

## Outline

We have the outline presented to us but it's a pretty abstract outline.
It helps having a picture to illustrate all of the components, see how they all interact. Then we can itemize our components for a bit more of a grnaular look.

![DesignLayout](../../assets/posts/a_cloud_resume/design.svg)

*S3 Bucket*
- Bucket
    - Upload the content
    - Account for the mime types of all our files
- Policy 
    - Public Access Blocks (The default block should be enabled, but we'll ensure it)
    - IAM Policy (To allow Cloudfront to access the S3 Bucket)

*Cloudfront*
- Distribution
    - Set origin as our S3 Bucket
    - Set the web root appropriately
    - Include aliases for our custom domains
    - Set caching policies as necessary for Origin Access Control

*DynamoDB*
- Tables
    - We need two tables: ConnectionIDS and ViewerCounts
- Stream
    - This is something that allows data changes to be propagated to the lambda function

*Lambda*
- Updater Function
    - On connection this function adds to connectionIds which will then increment the databse
- Stream function
    - This is the function that gets called after the dynamoDB instance increments the count, Lambda polls this and pushes the result to the websocket connection

*API Gateway*
- Websocket Route
    - A "connection" and "disconnect" trigger route
        - Integrated with the updater lambda function that handles those requests.

*Certificate Manager*
- For a custom domain

## NoSQL - DynamoDB

NoSQL differs a bit from a SQL database.
SQL you'd have to architect the entirety of your expected data ideally at the start. With NoSQL it offers quite a bit of flexibility, being a glorified map/dictionary you give it an id and it can have any kind of data after it

So our tables would basically be a column of connectionID's for one table and a column that is just an id that holds our current visitor count.
And apparently with NoSQL you can easily do that, you just define an id with which to index and the data after is just malleable.


## Functions

Now I haven't messed with lambda functions in AWS to specifically run code, I've had Docker containers run, which makes more sense to me, because Docker has all of the components for your code to run. So the Serverless arbitrary code execution seemed a bit more confusing to me because where do the dependencies come from? How do the inputs to the function actually get passed there?

The first one is easy enough, they have the predetermined environments you can run and any extra dependencies you need to import just like any other environment. So for instance if your function needs the `aws-sdk`, you require it, include it in the `package.json` and `npm install` or just `npm install <package>`. Then write your code, zip up the package and upload it. You have to be sure to write the function into `exports.function_name` so the environment can use it though. Yeah this is specifically Javascript, but the principle applies to the other environments.

But if I'm writing a function that's based on some request's event...how do I know what's in the event?

```js
exports.myfunc( (event) => {
    console.log(event)
});
```
Actually this is how. Because the AWS documentation even though it's pretty explanatory in some areas,  with regards to the exact reference to which payload gets passed where it...isn't obvious. As expected, AI can spit it out extremely easily, but even asking AI where it got that information actually links you to non-existent githubs or aspects of the AWS Documentation that don't work. This is a double edged sword to me because, I love the ease of use that AI can bring, It's an amazing speed increase in a lot areas but ultimately I should be able to reference the same knowledge base it has. It's probably out there, but it's just not being clear with me.
The AWS functions will be using an `AWS_PROXY` integration, since they'll be communicating between AWS services. It'll be a websocket and I found [this](https://docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-websocket-api-route-keys-connect-disconnect.html)
```js
 export const handler = async(event, context) => {
    const connectId = event["requestContext"]["connectionId"]
    const domainName = event["requestContext"]["domainName"]
    const stageName = event["requestContext"]["stage"]
    const qs = event['queryStringParameters']
    console.log('Connection ID: ', connectId, 'Domain Name: ', domainName, 'Stage Name: ', stageName, 'Query Strings: ', qs )
    return {"statusCode" : 200}
};
```

Which this gives you enough to work with, but is truly annoying that there's not a solid requestContext's for each integration for reference.

So how will our functions look?

```js 
// updater.js
require('aws-sdk');
const dynamodb = new AWS.DynamoDB.DocumentClient();

const CONNECTION_IDS_TABLE = process.env.CONNECTION_IDS_TABLE;
const VISITOR_COUNT_TABLE = process.env.VISITOR_COUNT_TABLE;
const VISITOR_COUNT_ITEM_ID = 'visitorCount';

exports.handler = async (event) => {
    console.log('DBUpdater Event:', JSON.stringify(event, null, 2));

    const connectionId = event.requestContext.connectionId;
    const eventType = event.requestContext.eventType;

    try {
        if (eventType === 'CONNECT') {
            await dynamodb.put({
                TableName: CONNECTION_IDS_TABLE,
                Item: { connectionId: connectionId }
            }).promise();
            console.log(`Connection ID ${connectionId} saved.`);

            await dynamodb.update({
                TableName: VISITOR_COUNT_TABLE,
                Key: { id: VISITOR_COUNT_ITEM_ID },
                UpdateExpression: 'ADD currentCount :inc',
                ExpressionAttributeValues: { ':inc': 1 },
                ReturnValues: 'UPDATED_NEW' // To trigger stream with new value
            }).promise();
            console.log("Visitor count incremented.");

        } else if (eventType === 'DISCONNECT') {
            // 1. Delete Connection ID
            await dynamodb.delete({
                TableName: CONNECTION_IDS_TABLE,
                Key: { connectionId: connectionId }
            }).promise();
            console.log(`Connection ID ${connectionId} deleted.`);
        } else {
            console.log(`Unhandled eventType: ${eventType}`);
        }

        return { statusCode: 200, body: 'OK' };
    } catch (error) {
        console.error("DBUpdater Error:", error);
        return { statusCode: 500, body: 'Error processing request' };
    }
};
```

```js
// stream.js
const AWS = require('aws-sdk');
const dynamodb = new AWS.DynamoDB.DocumentClient();

const CONNECTION_IDS_TABLE = process.env.CONNECTION_IDS_TABLE;

// This event contains a list of Records which have some StreamRecords in the dynamodb field
exports.handler = async (event) => {
    console.log('DBStreamProcessor Event:', JSON.stringify(event, null, 2));

    // Sets the endpoint for communication to the open WS connection
    const apigwManagementApi = new AWS.ApiGatewayManagementApi({
        apiVersion: '2018-11-29',
        endpoint: process.env.API_GATEWAY_MANAGEMENT_ENDPOINT // e.g., 'https://<api-id>.execute-api.<region>.amazonaws.com/prod'
    });

    let newVisitorCount = 0;
    if (event.Records && event.Records.length > 0) {
        const record = event.Records[0]; // Assuming only one record per invocation due to batch_size = 1
        if (record.eventName === 'MODIFY' || record.eventName === 'INSERT') {
            const newImage = AWS.DynamoDB.Converter.unmarshall(record.dynamodb.NewImage);
            newVisitorCount = newImage.currentCount || 0;
            console.log(`New Visitor Count from stream: ${newVisitorCount}`);
        } else {
            console.log("Not an INSERT or MODIFY event, skipping count update.");
            return { statusCode: 200, body: 'No update needed.' };
        }
    } else {
        console.log("No records in stream event, skipping.");
        return { statusCode: 200, body: 'No records.' };
    }

    try {
        // Grabbing all active connections to send the updated message count
        const connectionData = await dynamodb.scan({ TableName: CONNECTION_IDS_TABLE }).promise();
        const connectionIds = connectionData.Items.map(item => item.connectionId);
        console.log(`Active connections: ${connectionIds.length}`);

        const postData = JSON.stringify({ count: newVisitorCount });

        const postCalls = connectionIds.map(async (connectionId) => {
            try {
                await apigwManagementApi.postToConnection({ ConnectionId: connectionId, Data: postData }).promise();
                console.log(`Message sent to ${connectionId}`);
            } catch (e) {
                if (e.statusCode === 410) { // GoneException - connection no longer exists
                    console.log(`Stale connection ${connectionId}, deleting.`);
                    await dynamodb.delete({ TableName: CONNECTION_IDS_TABLE, Key: { connectionId: connectionId } }).promise();
                } else {
                    console.error(`Failed to post to connection ${connectionId}:`, e);
                }
            }
        });

        await Promise.all(postCalls); 

        return { statusCode: 200, body: 'Data sent.' };
    } catch (err) {
        console.error("DBStreamProcessor Error:", err);
        return { statusCode: 500, body: JSON.stringify(err) };
    }
};
```


## The Terraform

Now I suppose we can start building it?
I opt'd for a directory structure like this:
```
.
├── lambda_functions
├── node_modules
├── src
└── terraform_deployment
```

Where src, is the webpage and I'm not unnecessarily packaging in excess node_modules I used for styling the website (using tailwind).


The actual IaC build is in the MVP I linked above, so I'm not going to rehash the entire terraform configuration, just some interesting tidbits I came across.


The way you can include policies directly inside the configuration, as well as it not being a direct JSON file makes the readability of it much nicer.
```terraform
resource "aws_iam_role" "db_stream_processor_lambda_role" {
  name = "${local.stream_lambda}-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "lambda.amazonaws.com"
      }
    }]
  })
  tags = {
    Project   = var.project_name
    ManagedBy = "Terraform"
  }
}
```



How lambda specifies function names. It feels very similar to python's import syntax actually:
File.Function
```terraform
resource "aws_lambda_function" "db_updater_lambda" {
  function_name    = local.updater_lambda
  handler          = "index.handler"
  runtime          = "nodejs20.x"
  role             = aws_iam_role.db_updater_lambda_role.arn
  filename         = data.archive_file.db_updater_zip.output_path
  source_code_hash = data.archive_file.db_updater_zip.output_base64sha256
  timeout          = 10
  memory_size      = 128

  environment {
    variables = {
      CONNECTION_IDS_TABLE = aws_dynamodb_table.connection_ids_table.name
      VISITOR_COUNT_TABLE  = aws_dynamodb_table.visitor_count_table.name
    }
  }

  tags = {
    Project   = var.project_name
    ManagedBy = "Terraform"
  }
}

```

And two struggle points I had, one was surprisingly Cloudfront. Because I never actually used the OAC for a bucket before, I have a deploy script for an S3 website hosted by cloudfront that actually uses DefaultCacheBehavior rather than explicit policies. And this is apparently the more modern way to do it, as you can save custom policies to reuse, which is very convenient. And to use the modernized OAC, you need these policies, or you get some very friendly deployment errors :)
```terraform
data "aws_cloudfront_cache_policy" "caching_optimized" {
  name = "Managed-CachingOptimized"
}

data "aws_cloudfront_origin_request_policy" "caching_optimized_request" {
  name = "Managed-AllViewerExceptHostHeader"
}
```


And of course, dealing with the chicken-egg problem of your code needs to connect to a websocket endpoint, but you don't have that URL until you deploy the websocket endpoint. 
So there was a bit of manual intervention, doing a terraform apply, grabbing the endpoint and then replacing it in the .js file for my website, re-applying and then invalidating the cloudfront cache.
Now I write this out though and I see that a templatefile is likely the way to go just having it depend on the output of of the API gateway, since it doesn't need the Cloudfront distribution to exist.

This will segue nicely into my next steps, which is actually putting this in a CI/CD pipeline, which may be a little excessive for a static website I probably won't change too much, but It's a learning experience afterall.










