# Pure policy construction: keeping this module provider-free lets the contract
# test evaluate the exact JSON without AWS credentials or a plan/apply.
locals {
  ec2_prefix = "arn:${var.partition}:ec2:${var.region}:${var.account_id}"
  required_tags = {
    "aws:RequestTag/CatsIssue"   = "124"
    "aws:RequestTag/CatsPurpose" = "temporary-worker-qualification"
  }

  policy = {
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "ReadRegionalEc2AndSsmInventory"
        Effect   = "Allow"
        Action   = ["ec2:DescribeImages", "ec2:DescribeInstances", "ec2:DescribeInstanceStatus", "ec2:DescribeVolumes", "ssm:DescribeInstanceInformation"]
        Resource = "*"
        Condition = {
          StringEquals = { "aws:RequestedRegion" = var.region }
        }
      },
      # SSM does not expose command-invocation resource ARNs for these APIs.
      # Bind the unavoidable wildcard to the one qualification region; the
      # tool also supplies and revalidates an exact instance/command pair.
      {
        Sid      = "ReadRegionalSsmCommandResult"
        Effect   = "Allow"
        Action   = "ssm:GetCommandInvocation"
        Resource = "*"
        Condition = {
          StringEquals = { "aws:RequestedRegion" = var.region }
        }
      },
      {
        Sid      = "CancelRegionalSsmCommand"
        Effect   = "Allow"
        Action   = "ssm:CancelCommand"
        Resource = "*"
        Condition = {
          StringEquals = { "aws:RequestedRegion" = var.region }
        }
      },
      # AWS evaluates RunInstances once for every participating resource.
      # Existing/fixed resources cannot carry request-tag or instance-profile
      # conditions; applying those conditions here makes a real launch fail.
      {
        Sid    = "LaunchWithFixedInfrastructure"
        Effect = "Allow"
        Action = "ec2:RunInstances"
        Resource = concat([
          "arn:${var.partition}:ec2:${var.region}::image/${var.ami_id}",
          "${local.ec2_prefix}:subnet/${var.subnet_id}",
          "${local.ec2_prefix}:security-group/${var.security_group_id}",
          ], [
          # EC2 snapshot ARNs have an empty account segment. The caller
          # resolves this exact set from the fixed AMI rather than granting
          # arbitrary snapshots that could be exposed through a new volume.
          for arn in var.snapshot_arns : arn
        ])
      },
      {
        Sid      = "LaunchPrivateInterfaceInFixedSubnet"
        Effect   = "Allow"
        Action   = "ec2:RunInstances"
        Resource = "${local.ec2_prefix}:network-interface/*"
        Condition = {
          ArnEquals = { "ec2:Subnet" = "${local.ec2_prefix}:subnet/${var.subnet_id}" }
          Bool      = { "ec2:AssociatePublicIpAddress" = "false" }
        }
      },
      {
        Sid      = "LaunchTaggedQualificationInstance"
        Effect   = "Allow"
        Action   = "ec2:RunInstances"
        Resource = "${local.ec2_prefix}:instance/*"
        Condition = {
          StringEquals = merge(local.required_tags, {
            "ec2:InstanceType"         = var.instance_type
            "ec2:MetadataHttpEndpoint" = "enabled"
            "ec2:MetadataHttpTokens"   = "required"
          })
          NumericEquals = { "ec2:MetadataHttpPutResponseHopLimit" = "2" }
          ArnEquals = {
            "ec2:InstanceProfile" = var.instance_profile_arn
          }
        }
      },
      {
        Sid      = "LaunchTaggedEncryptedRootVolume"
        Effect   = "Allow"
        Action   = "ec2:RunInstances"
        Resource = "${local.ec2_prefix}:volume/*"
        Condition = {
          StringEquals = merge(local.required_tags, {
            "ec2:VolumeType" = "gp3"
          })
          Bool = {
            "ec2:Encrypted" = "true"
          }
          NumericEquals = {
            "ec2:VolumeSize" = "200"
          }
          # Bind every created EBS volume back to one of the fixed AMI's
          # snapshots. This complements the exact snapshot resources above.
          ArnEquals = {
            "ec2:ParentSnapshot" = var.snapshot_arns
          }
        }
      },
      {
        Sid      = "TagOnlyDuringLaunch"
        Effect   = "Allow"
        Action   = "ec2:CreateTags"
        Resource = ["${local.ec2_prefix}:instance/*", "${local.ec2_prefix}:volume/*"]
        Condition = {
          StringEquals = { "ec2:CreateAction" = "RunInstances" }
          "ForAllValues:StringEquals" = {
            "aws:TagKeys" = ["Name", "Project", "CatsIssue", "CatsPurpose", "CatsNodeId", "CatsRunId", "CatsSourceSha"]
          }
        }
      },
      {
        Sid      = "OperateOnlyQualificationInstances"
        Effect   = "Allow"
        Action   = ["ec2:ModifyInstanceAttribute", "ec2:TerminateInstances"]
        Resource = "${local.ec2_prefix}:instance/*"
        Condition = {
          StringEquals = {
            "ec2:ResourceTag/CatsIssue"   = "124"
            "ec2:ResourceTag/CatsPurpose" = "temporary-worker-qualification"
          }
        }
      },
      {
        Sid      = "PassOnlyWorkerRoleToEc2"
        Effect   = "Allow"
        Action   = "iam:PassRole"
        Resource = var.worker_role_arn
        Condition = {
          StringEquals = { "iam:PassedToService" = "ec2.amazonaws.com" }
        }
      },
      {
        Sid      = "UseReviewedSsmDocument"
        Effect   = "Allow"
        Action   = "ssm:SendCommand"
        Resource = "arn:${var.partition}:ssm:${var.region}::document/AWS-RunShellScript"
      },
      {
        Sid      = "CommandOnlyQualificationInstances"
        Effect   = "Allow"
        Action   = "ssm:SendCommand"
        Resource = "${local.ec2_prefix}:instance/*"
        Condition = {
          StringEquals = {
            "ssm:resourceTag/CatsIssue"   = "124"
            "ssm:resourceTag/CatsPurpose" = "temporary-worker-qualification"
          }
        }
      },
      {
        Sid      = "QualificationBundleBucketLocation"
        Effect   = "Allow"
        Action   = "s3:GetBucketLocation"
        Resource = var.artifact_bucket_arn
      },
      {
        Sid      = "ListQualificationBundlePrefix"
        Effect   = "Allow"
        Action   = "s3:ListBucket"
        Resource = var.artifact_bucket_arn
        Condition = {
          StringLike = { "s3:prefix" = "worker/qualification-124/*" }
        }
      },
      {
        Sid      = "QualificationBundles"
        Effect   = "Allow"
        Action   = ["s3:GetObject", "s3:PutObject"]
        Resource = "${var.artifact_bucket_arn}/worker/qualification-124/*"
      },
    ]
  }

  policy_json = jsonencode(local.policy)
}
