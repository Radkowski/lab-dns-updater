data "aws_caller_identity" "current" {}
data "aws_region" "current" {}



variable "DEPLOYMENTPREFIX" {}
variable "S3_INFO" {}
variable "AUTHTAGS" {}



resource "aws_iam_role" "event-role" {
  name = join("", [var.DEPLOYMENTPREFIX, "-eventbridge-role"])
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Sid    = ""
        Principal = {
          Service = "events.amazonaws.com"
        }
      },
    ]
  })
  inline_policy {
    name = join("", [var.DEPLOYMENTPREFIX, "-event-policy"])
    policy = jsonencode({
      "Version" : "2012-10-17",
      "Statement" : [
        {
          "Effect" : "Allow",
          "Action" : [
            "codepipeline:StartPipelineExecution"
          ],
          "Resource" : [aws_codepipeline.codepipeline.arn]
        }
      ]
    })
  }
}


resource "aws_iam_role" "lambda-role" {
  name = join("", [var.DEPLOYMENTPREFIX, "-lambda-role"])
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Sid    = ""
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      },
    ]
  })
  inline_policy {
    name = join("", [var.DEPLOYMENTPREFIX, "-lambda-deploy-policy"])

    policy = jsonencode({
      "Version" : "2012-10-17",
      "Statement" : [
        {
          "Sid" : "log0",
          "Effect" : "Allow",
          "Action" : "logs:CreateLogGroup",
          "Resource" : join("", ["arn:aws:logs:", data.aws_region.current.name, ":", data.aws_caller_identity.current.account_id, ":*"])
        },
        {
          "Sid" : "log1",
          "Effect" : "Allow",
          "Action" : [
            "logs:CreateLogStream",
            "logs:PutLogEvents"
          ],
          "Resource" : [
            join("", ["arn:aws:logs:", data.aws_region.current.name, ":", data.aws_caller_identity.current.account_id, ":", "log-group:/aws/lambda/", var.DEPLOYMENTPREFIX, "-lambda:*"])
          ]
        },
        {
          "Sid" : "codepipeline",
          "Effect" : "Allow",
          "Action" : [
            "codepipeline:PutJobSuccessResult",
            "codepipeline:PutJobFailureResult"
          ],
          "Resource" : "*"
        },
        {
          "Sid" : "route53",
          "Effect" : "Allow",
          "Action" : [
            "route53:ListHostedZonesByName",
            "route53:GetHostedZone",
            "route53:ListResourceRecordSets",
            "route53:ChangeResourceRecordSets",
          ],
          "Resource" : "*"
        },
        {
          "Sid" : "ec2",
          "Effect" : "Allow",
          "Action" : [
            "ec2:DescribeInstances",
          ],
          "Resource" : "*"
        },
      ]
    })
  }
}


resource "aws_iam_role" "codepipeline-role" {
  name = join("", [var.DEPLOYMENTPREFIX, "-codepipeline-role"])
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Sid    = ""
        Principal = {
          Service = "codepipeline.amazonaws.com"
        }
      },
    ]
  })
  inline_policy {
    name = join("", [var.DEPLOYMENTPREFIX, "-codepipeline-inline-policy"])
    policy = jsonencode({
      "Statement" : [
        {
          "Action" : [
            "iam:PassRole"
          ],
          "Resource" : "*",
          "Effect" : "Allow",
          "Condition" : {
            "StringEqualsIfExists" : {
              "iam:PassedToService" : [
                "cloudformation.amazonaws.com",
                "elasticbeanstalk.amazonaws.com",
                "ec2.amazonaws.com",
                "ecs-tasks.amazonaws.com"
              ]
            }
          }
        },
        {
          "Action" : [
            "codecommit:CancelUploadArchive",
            "codecommit:GetBranch",
            "codecommit:GetCommit",
            "codecommit:GetRepository",
            "codecommit:GetUploadArchiveStatus",
            "codecommit:UploadArchive"
          ],
          "Resource" : "*",
          "Effect" : "Allow"
        },
        {
          "Action" : [
            "codedeploy:CreateDeployment",
            "codedeploy:GetApplication",
            "codedeploy:GetApplicationRevision",
            "codedeploy:GetDeployment",
            "codedeploy:GetDeploymentConfig",
            "codedeploy:RegisterApplicationRevision"
          ],
          "Resource" : "*",
          "Effect" : "Allow"
        },
        {
          "Action" : [
            "codestar-connections:UseConnection"
          ],
          "Resource" : "*",
          "Effect" : "Allow"
        },
        {
          "Action" : [
            "elasticbeanstalk:*",
            "ec2:*",
            "elasticloadbalancing:*",
            "autoscaling:*",
            "cloudwatch:*",
            "s3:*",
            "sns:*",
            "cloudformation:*",
            "rds:*",
            "sqs:*",
            "ecs:*",
            "ecr:*"
          ],
          "Resource" : "*",
          "Effect" : "Allow"
        },
        {
          "Action" : [
            "lambda:InvokeFunction",
            "lambda:ListFunctions"
          ],
          "Resource" : "*",
          "Effect" : "Allow"
        },
        {
          "Action" : [
            "opsworks:CreateDeployment",
            "opsworks:DescribeApps",
            "opsworks:DescribeCommands",
            "opsworks:DescribeDeployments",
            "opsworks:DescribeInstances",
            "opsworks:DescribeStacks",
            "opsworks:UpdateApp",
            "opsworks:UpdateStack"
          ],
          "Resource" : "*",
          "Effect" : "Allow"
        },
        {
          "Action" : [
            "cloudformation:CreateStack",
            "cloudformation:DeleteStack",
            "cloudformation:DescribeStacks",
            "cloudformation:UpdateStack",
            "cloudformation:CreateChangeSet",
            "cloudformation:DeleteChangeSet",
            "cloudformation:DescribeChangeSet",
            "cloudformation:ExecuteChangeSet",
            "cloudformation:SetStackPolicy",
            "cloudformation:ValidateTemplate"
          ],
          "Resource" : "*",
          "Effect" : "Allow"
        },
        {
          "Action" : [
            "codebuild:BatchGetBuilds",
            "codebuild:StartBuild",
            "codebuild:BatchGetBuildBatches",
            "codebuild:StartBuildBatch"
          ],
          "Resource" : "*",
          "Effect" : "Allow"
        },
        {
          "Effect" : "Allow",
          "Action" : [
            "devicefarm:ListProjects",
            "devicefarm:ListDevicePools",
            "devicefarm:GetRun",
            "devicefarm:GetUpload",
            "devicefarm:CreateUpload",
            "devicefarm:ScheduleRun"
          ],
          "Resource" : "*"
        },
        {
          "Effect" : "Allow",
          "Action" : [
            "servicecatalog:ListProvisioningArtifacts",
            "servicecatalog:CreateProvisioningArtifact",
            "servicecatalog:DescribeProvisioningArtifact",
            "servicecatalog:DeleteProvisioningArtifact",
            "servicecatalog:UpdateProduct"
          ],
          "Resource" : "*"
        },
        {
          "Effect" : "Allow",
          "Action" : [
            "cloudformation:ValidateTemplate"
          ],
          "Resource" : "*"
        },
        {
          "Effect" : "Allow",
          "Action" : [
            "ecr:DescribeImages"
          ],
          "Resource" : "*"
        },
        {
          "Effect" : "Allow",
          "Action" : [
            "states:DescribeExecution",
            "states:DescribeStateMachine",
            "states:StartExecution"
          ],
          "Resource" : "*"
        },
        {
          "Effect" : "Allow",
          "Action" : [
            "appconfig:StartDeployment",
            "appconfig:StopDeployment",
            "appconfig:GetDeployment"
          ],
          "Resource" : "*"
        }
      ],
      "Version" : "2012-10-17"
      }
    )
  }
}


data "archive_file" "lambda-code" {
  type = "zip"
  output_path = "lambda-code.zip"
  source {
    content  = <<EOF
import boto3
import json
from datetime import datetime
import logging
import pprint

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# CREATE|DELETE|UPSERT


def read_config_file(s3_details,s3_credentials):       
        session = boto3.session.Session(
            aws_access_key_id=s3_credentials['accessKeyId'],
            aws_secret_access_key=s3_credentials['secretAccessKey'],
            aws_session_token=s3_credentials['sessionToken']
            )
        print (session)
        s3 = session.resource('s3')
        bucket =  s3_details['bucketName']
        key = s3_details['objectKey']
        obj = s3.Object(bucket, key)
        data = obj.get()['Body'].read().decode('utf-8')
        json_data = json.loads(data)
        return(json_data)


def put_job_success(job):
    client_code_pipeline = boto3.client('codepipeline')
    # print('Putting job ',job,' success')
    logger.info ('Putting job '+job+' success.')
    client_code_pipeline.put_job_success_result(jobId=job)
    return 0

    
def extract_weight(Tags,DefaultWeight):
    for x in Tags:
          if x['Key'] == 'DNSRecordWeight':
               return int(x['Value'])
    return int(DefaultWeight)

     
def verify_instance_tags(tag_list,value):
    for x in tag_list:
          if x["Key"] == "DNSRecord" and x["Value"] == value:
               return True
    return False


def find_ec2(vpc_id, DNSRecord, DefaultWeight):
    dt_string = int(datetime.now().strftime("%y%m%d%H%M"))
    counter=0
    results=[]
    ec2 = boto3.resource('ec2')
    for instance in ec2.instances.all():
        if (instance.state['Code'] <= 16):
            if  (instance.vpc_id == vpc_id) and verify_instance_tags(instance.tags,DNSRecord):
                results.append([instance.id, instance.private_ip_address,extract_weight(instance.tags,DefaultWeight),str(dt_string+counter)])
                counter +=1
    return results


def check_vpc_association (vpc_list, vpc_id):
     result=False
     for x in vpc_list:
          if x['VPCId'] == vpc_id:
               result = True
     return result


def verify_domain(domain_id, domain_name, vpc_id):
        cl_r53 = boto3.client('route53')
        response = cl_r53.get_hosted_zone(Id=domain_id)
        if  not (response['HostedZone']['Config']['PrivateZone']):
            # print('Hosted zone is Public')
            return False
        if (response['HostedZone']['Name'][:-1]!= domain_name):
            #  print('Zone does not match domain name:',response['HostedZone']['Name'])
             return False
        if not (check_vpc_association (response['VPCs'], vpc_id)):
            #  print('Hosted zone is not associated with configured VPC')
             return False
        logger.info ('Domain '+domain_name+' has been found and has ' + domain_id +' ID.' )
        return (domain_id)


def find_domain(domain_name,vpc_id):
    results=[]
    cl_r53 = boto3.client('route53')
    response = cl_r53.list_hosted_zones_by_name()
    for x in response['HostedZones']:
        results.append(verify_domain(x['Id'][12:],domain_name,vpc_id))
    selected_domain = (list(filter(None, results)))
    if len(selected_domain) == 1:
         return (selected_domain[0])
    return False


def update_dns_record(zone_id,action,record_set):
    cl_r53 = boto3.client('route53')
    response = cl_r53.change_resource_record_sets(
        HostedZoneId=zone_id,
        ChangeBatch={
            'Comment': 'Update made by Radkowski Magic Automation',
            'Changes':  [
                {
                    'Action': action,
                    'ResourceRecordSet': record_set
                }
                        ]
                    }
            )
    logger.info ('Update '+ str(record_set)+' with action: '+action)
    return 0


def list_resources (zone_id, start_record_name):
    results = []
    cl_r53 = boto3.client('route53')
    response = cl_r53.list_resource_record_sets(
    HostedZoneId=zone_id,
    StartRecordName=start_record_name,
    StartRecordType='A',
    MaxItems='100')
    for x in response['ResourceRecordSets']:
        if x['Name'][:-1] == start_record_name and x['Type'] =='A':
             results.append(x)
    return results


def clean_records(zone_id,list_record_sets):
    for x in list_record_sets:
          update_dns_record(zone_id, 'DELETE',x)
    return 0


def add_records(zone_id,list_record_sets):
    for x in list_record_sets:
          update_dns_record(zone_id, 'UPSERT',x)
    return 0    
      

def create_list_record_sets(ec2_list,DNSRecord,DefaultTTL):
    list_record_sets = []
    for x in ec2_list:
        skel = {'Name': DNSRecord,
                'ResourceRecords': [{'Value': x[1]}],
                'SetIdentifier': x[3],
                'TTL': DefaultTTL,
                'Type': 'A',
                'Weight': x[2]
               }
        list_record_sets.append(skel)
    return (list_record_sets)


def lambda_handler(event, context):
    s3_details      = (event['CodePipeline.job']['data']['inputArtifacts'][0]['location']['s3Location'])
    s3_credentials  = (event['CodePipeline.job']['data']['artifactCredentials'])
    configuration   = (read_config_file(s3_details,s3_credentials))

    vpc_id          = configuration['Network']['Vpc_id']
    HostName        = configuration['Route53']['HostName']
    DomainName      = configuration['Route53']['DomainName']
    DefaultWeight   = configuration['Route53']['DefaultWeight']
    DefaultTTL      = configuration['Route53']['DefaultTTL']
    WipeBeforeAdd   = configuration['Settings']['WipeBeforeAdd']
    
    DNSRecord       = HostName +'.' + DomainName
    zone_id         = find_domain(DomainName,vpc_id)

    logger.info ('Read following from the config file: '+vpc_id +' '+HostName+' '+DomainName+' '+str(DefaultWeight)+' '+str(DefaultTTL)+' '+str(WipeBeforeAdd))

    if not zone_id:
        logger.info ('Cannot find defined zone: '+ DomainName +' -> EXITING' )
        put_job_success(event['CodePipeline.job']['id'])
        return 0

    candidates = find_ec2(vpc_id, DNSRecord, DefaultWeight)
    if len(candidates) == 0:
        logger.info('Pipeline trigerred but no EC2 candidates found')
        put_job_success(event['CodePipeline.job']['id'])
        return 0
        
        
    if WipeBeforeAdd:
        clean_records(zone_id,list_resources(zone_id,DNSRecord))

    add_records(zone_id,(create_list_record_sets(candidates,DNSRecord,DefaultTTL)))

    put_job_success(event['CodePipeline.job']['id'])
    return 0

EOF
    filename = "lambda_function.py"
  }
}


resource "aws_lambda_function" "lambda" {
  description      = "Publish new version and create AppSpec file [RadkowskiLab]"
  architectures    = ["arm64"]
  filename         = data.archive_file.lambda-code.output_path
  source_code_hash = data.archive_file.lambda-code.output_base64sha256
  role             = aws_iam_role.lambda-role.arn
  function_name    = join("", [var.DEPLOYMENTPREFIX, "-lambda"])
  handler          = "lambda_function.lambda_handler"
  runtime          = "python3.11"
  timeout          = 60
  memory_size      = 256
  tags             = var.AUTHTAGS
}


resource "aws_codepipeline" "codepipeline" {
  name     = join("", [var.DEPLOYMENTPREFIX, "-pipeline"])
  role_arn = aws_iam_role.codepipeline-role.arn
  artifact_store {
    location = var.S3_INFO.bucket
    type     = "S3"
  }
  stage {
    name = "Source"
    action {
      name             = "Read_source"
      category         = "Source"
      owner            = "AWS"
      provider         = "S3"
      version          = "1"
      output_artifacts = ["SourceArtifact"]
      configuration = {
        S3Bucket             = var.S3_INFO.bucket
        S3ObjectKey          = "config.json"
        PollForSourceChanges = false
      }
    }
  }
  stage {
    name = "Invoke-Lambda"
    action {
      name            = "Update_Route53"
      category        = "Invoke"
      owner           = "AWS"
      provider        = "Lambda"
      version         = "1"
      input_artifacts = ["SourceArtifact"]
      configuration = {
        FunctionName = aws_lambda_function.lambda.function_name
      }
    }
  }
}


resource "aws_cloudwatch_event_rule" "start-pipeline-after-s3-push" {
  name        = join("", [var.DEPLOYMENTPREFIX, "-s3-rule"])
  description = "Starts pipeline once lambda zip is pushed into s3"
  event_pattern = jsonencode({
    "source" : ["aws.s3"],
    "detail-type" : ["AWS API Call via CloudTrail"],
    "detail" : {
      "eventSource" : ["s3.amazonaws.com"],
      "eventName" : ["PutObject", "CompleteMultipartUpload", "CopyObject"],
      "requestParameters" : {
        "bucketName" : [var.S3_INFO.bucket],
        "key" : ["config.json"]
      }
  } })
}


resource "aws_cloudwatch_event_rule" "start-pipeline-after-ec2-state-change" {
  name        = join("", [var.DEPLOYMENTPREFIX, "-ec2-rule"])
  description = "Starts pipeline once EC2 state is changed"
  event_pattern = jsonencode({
    "source" : ["aws.ec2"],
    "detail-type" : ["EC2 Instance State-change Notification"]
  })
}


resource "aws_cloudwatch_event_rule" "start-pipeline-after-tag-change" {
  name        = join("", [var.DEPLOYMENTPREFIX, "-tag-rule"])
  description = "Starts pipeline once TAG is changed"
  event_pattern = jsonencode({
    "source" : ["aws.tag"],
    "detail-type" : ["Tag Change on Resource"],
    "detail" : {
      "service" : ["ec2"],
      "resource-type" : ["instance"]
    }
  })
}


resource "aws_cloudwatch_event_target" "s3-trigger" {
  rule      = aws_cloudwatch_event_rule.start-pipeline-after-s3-push.name
  target_id = join("", [var.DEPLOYMENTPREFIX, "-triggerCP"])
  arn       = aws_codepipeline.codepipeline.arn
  role_arn  = aws_iam_role.event-role.arn
}


resource "aws_cloudwatch_event_target" "ec2-trigger" {
  rule      = aws_cloudwatch_event_rule.start-pipeline-after-ec2-state-change.name
  target_id = join("", [var.DEPLOYMENTPREFIX, "-triggerCP"])
  arn       = aws_codepipeline.codepipeline.arn
  role_arn  = aws_iam_role.event-role.arn
}


resource "aws_cloudwatch_event_target" "tags-trigger" {
  rule      = aws_cloudwatch_event_rule.start-pipeline-after-tag-change.name
  target_id = join("", [var.DEPLOYMENTPREFIX, "-triggerCP"])
  arn       = aws_codepipeline.codepipeline.arn
  role_arn  = aws_iam_role.event-role.arn
}