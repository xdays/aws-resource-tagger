#!/usr/bin/env python3
"""
Tag all taggable AWS resources with their primary identifier.

This script discovers resources using each service's native API and tags them
using the AWS Resource Groups Tagging API where possible, or service-specific
tagging APIs as fallback.

The tag key is defined by AWS_IDENTIFIER_TAG_KEY environment variable,
and the value is the resource's primary identifier.

Usage:
    export AWS_IDENTIFIER_TAG_KEY="ResourceIdentifier"
    python tag_resources.py [--dry-run] [--service SERVICE] [--region REGION]

Requirements:
    - boto3
    - AWS credentials with appropriate permissions
"""

import argparse
import json
import os
import sys
from dataclasses import dataclass
from typing import Callable

try:
    import boto3
    from botocore.exceptions import ClientError, NoCredentialsError, OperationNotPageableError
except ImportError:
    print("Error: boto3 is required. Install with: pip install boto3")
    sys.exit(1)


@dataclass
class ResourceConfig:
    """Configuration for discovering and tagging a resource type."""
    service: str
    resource_type: str
    client_name: str
    list_method: str
    list_key: str
    id_attr: str
    arn_attr: str = None
    arn_template: str = None
    list_kwargs: dict = None
    nested_key: str = None
    # For services that need special handling
    custom_list: Callable = None
    custom_tag: Callable = None


class ResourceTagger:
    def __init__(self, region: str, dry_run: bool = False):
        self.region = region
        self.dry_run = dry_run
        self.tag_key = self._get_tag_key()
        self.session = boto3.Session(region_name=region)
        self.account_id = self._get_account_id()
        self.tagging_client = self.session.client("resourcegroupstaggingapi")

        # Counters
        self.tagged_count = 0
        self.error_count = 0
        self.skipped_count = 0

        # Build resource configurations
        self.resource_configs = self._build_resource_configs()

    def _get_tag_key(self):
        tag_key = os.environ.get("AWS_IDENTIFIER_TAG_KEY")
        if not tag_key:
            print("Error: AWS_IDENTIFIER_TAG_KEY environment variable is not set")
            sys.exit(1)
        return tag_key

    def _get_account_id(self):
        sts = self.session.client("sts")
        return sts.get_caller_identity()["Account"]

    def _build_resource_configs(self) -> list[ResourceConfig]:
        """Build configuration for all supported taggable resources."""
        configs = []

        # ============================================================
        # EC2 Resources
        # ============================================================
        ec2_resources = [
            ("Instance", "describe_instances", "Reservations", "InstanceId", "Instances"),
            ("Volume", "describe_volumes", "Volumes", "VolumeId", None),
            ("Snapshot", "describe_snapshots", "Snapshots", "SnapshotId", None),
            ("SecurityGroup", "describe_security_groups", "SecurityGroups", "GroupId", None),
            ("Subnet", "describe_subnets", "Subnets", "SubnetId", None),
            ("VPC", "describe_vpcs", "Vpcs", "VpcId", None),
            ("InternetGateway", "describe_internet_gateways", "InternetGateways", "InternetGatewayId", None),
            ("NatGateway", "describe_nat_gateways", "NatGateways", "NatGatewayId", None),
            ("NetworkInterface", "describe_network_interfaces", "NetworkInterfaces", "NetworkInterfaceId", None),
            ("RouteTable", "describe_route_tables", "RouteTables", "RouteTableId", None),
            ("NetworkAcl", "describe_network_acls", "NetworkAcls", "NetworkAclId", None),
            ("VpcEndpoint", "describe_vpc_endpoints", "VpcEndpoints", "VpcEndpointId", None),
            ("VpnGateway", "describe_vpn_gateways", "VpnGateways", "VpnGatewayId", None),
            ("CustomerGateway", "describe_customer_gateways", "CustomerGateways", "CustomerGatewayId", None),
            ("DhcpOptions", "describe_dhcp_options", "DhcpOptions", "DhcpOptionsId", None),
            ("EgressOnlyInternetGateway", "describe_egress_only_internet_gateways", "EgressOnlyInternetGateways", "EgressOnlyInternetGatewayId", None),
            ("ElasticIp", "describe_addresses", "Addresses", "AllocationId", None),
            ("FlowLog", "describe_flow_logs", "FlowLogs", "FlowLogId", None),
            ("KeyPair", "describe_key_pairs", "KeyPairs", "KeyPairId", None),
            ("LaunchTemplate", "describe_launch_templates", "LaunchTemplates", "LaunchTemplateId", None),
            ("PlacementGroup", "describe_placement_groups", "PlacementGroups", "GroupId", None),
            ("PrefixList", "describe_managed_prefix_lists", "PrefixLists", "PrefixListId", None),
            ("TransitGateway", "describe_transit_gateways", "TransitGateways", "TransitGatewayId", None),
            ("TransitGatewayAttachment", "describe_transit_gateway_attachments", "TransitGatewayAttachments", "TransitGatewayAttachmentId", None),
            ("TransitGatewayRouteTable", "describe_transit_gateway_route_tables", "TransitGatewayRouteTables", "TransitGatewayRouteTableId", None),
        ]

        for res_type, method, key, id_attr, nested in ec2_resources:
            list_kwargs = {}
            if res_type == "Snapshot":
                list_kwargs = {"OwnerIds": ["self"]}

            configs.append(ResourceConfig(
                service="EC2",
                resource_type=res_type,
                client_name="ec2",
                list_method=method,
                list_key=key,
                id_attr=id_attr,
                nested_key=nested,
                list_kwargs=list_kwargs,
                arn_template=f"arn:aws:ec2:{self.region}:{self.account_id}:{res_type.lower()}/{{id}}"
            ))

        # EC2 Images (AMIs) - owned by self
        configs.append(ResourceConfig(
            service="EC2",
            resource_type="Image",
            client_name="ec2",
            list_method="describe_images",
            list_key="Images",
            id_attr="ImageId",
            list_kwargs={"Owners": ["self"]},
            arn_template=f"arn:aws:ec2:{self.region}::image/{{id}}"
        ))

        # ============================================================
        # S3 Buckets (global, but tags are regional)
        # ============================================================
        configs.append(ResourceConfig(
            service="S3",
            resource_type="Bucket",
            client_name="s3",
            list_method="list_buckets",
            list_key="Buckets",
            id_attr="Name",
            arn_template="arn:aws:s3:::{id}"
        ))

        # ============================================================
        # Lambda Functions
        # ============================================================
        configs.append(ResourceConfig(
            service="Lambda",
            resource_type="Function",
            client_name="lambda",
            list_method="list_functions",
            list_key="Functions",
            id_attr="FunctionName",
            arn_attr="FunctionArn"
        ))

        # ============================================================
        # RDS Resources
        # ============================================================
        configs.append(ResourceConfig(
            service="RDS",
            resource_type="DBInstance",
            client_name="rds",
            list_method="describe_db_instances",
            list_key="DBInstances",
            id_attr="DBInstanceIdentifier",
            arn_attr="DBInstanceArn"
        ))
        configs.append(ResourceConfig(
            service="RDS",
            resource_type="DBCluster",
            client_name="rds",
            list_method="describe_db_clusters",
            list_key="DBClusters",
            id_attr="DBClusterIdentifier",
            arn_attr="DBClusterArn"
        ))
        configs.append(ResourceConfig(
            service="RDS",
            resource_type="DBSnapshot",
            client_name="rds",
            list_method="describe_db_snapshots",
            list_key="DBSnapshots",
            id_attr="DBSnapshotIdentifier",
            arn_attr="DBSnapshotArn"
        ))
        configs.append(ResourceConfig(
            service="RDS",
            resource_type="DBClusterSnapshot",
            client_name="rds",
            list_method="describe_db_cluster_snapshots",
            list_key="DBClusterSnapshots",
            id_attr="DBClusterSnapshotIdentifier",
            arn_attr="DBClusterSnapshotArn"
        ))
        configs.append(ResourceConfig(
            service="RDS",
            resource_type="DBSubnetGroup",
            client_name="rds",
            list_method="describe_db_subnet_groups",
            list_key="DBSubnetGroups",
            id_attr="DBSubnetGroupName",
            arn_attr="DBSubnetGroupArn"
        ))
        configs.append(ResourceConfig(
            service="RDS",
            resource_type="DBParameterGroup",
            client_name="rds",
            list_method="describe_db_parameter_groups",
            list_key="DBParameterGroups",
            id_attr="DBParameterGroupName",
            arn_attr="DBParameterGroupArn"
        ))
        configs.append(ResourceConfig(
            service="RDS",
            resource_type="OptionGroup",
            client_name="rds",
            list_method="describe_option_groups",
            list_key="OptionGroupsList",
            id_attr="OptionGroupName",
            arn_attr="OptionGroupArn"
        ))

        # ============================================================
        # DynamoDB Tables
        # ============================================================
        configs.append(ResourceConfig(
            service="DynamoDB",
            resource_type="Table",
            client_name="dynamodb",
            list_method="list_tables",
            list_key="TableNames",
            id_attr=None,  # List returns names directly
            arn_template=f"arn:aws:dynamodb:{self.region}:{self.account_id}:table/{{id}}"
        ))

        # ============================================================
        # SNS Topics
        # ============================================================
        configs.append(ResourceConfig(
            service="SNS",
            resource_type="Topic",
            client_name="sns",
            list_method="list_topics",
            list_key="Topics",
            id_attr="TopicArn",
            arn_attr="TopicArn"
        ))

        # ============================================================
        # SQS Queues
        # ============================================================
        configs.append(ResourceConfig(
            service="SQS",
            resource_type="Queue",
            client_name="sqs",
            list_method="list_queues",
            list_key="QueueUrls",
            id_attr=None,  # Returns URLs directly
            arn_template=f"arn:aws:sqs:{self.region}:{self.account_id}:{{id}}"
        ))

        # ============================================================
        # ECS Resources
        # ============================================================
        configs.append(ResourceConfig(
            service="ECS",
            resource_type="Cluster",
            client_name="ecs",
            list_method="list_clusters",
            list_key="clusterArns",
            id_attr=None,
            arn_attr=None  # Returns ARNs directly
        ))

        # ============================================================
        # EKS Clusters
        # ============================================================
        configs.append(ResourceConfig(
            service="EKS",
            resource_type="Cluster",
            client_name="eks",
            list_method="list_clusters",
            list_key="clusters",
            id_attr=None,
            arn_template=f"arn:aws:eks:{self.region}:{self.account_id}:cluster/{{id}}"
        ))

        # ============================================================
        # ElastiCache Resources
        # ============================================================
        configs.append(ResourceConfig(
            service="ElastiCache",
            resource_type="CacheCluster",
            client_name="elasticache",
            list_method="describe_cache_clusters",
            list_key="CacheClusters",
            id_attr="CacheClusterId",
            arn_attr="ARN"
        ))
        configs.append(ResourceConfig(
            service="ElastiCache",
            resource_type="ReplicationGroup",
            client_name="elasticache",
            list_method="describe_replication_groups",
            list_key="ReplicationGroups",
            id_attr="ReplicationGroupId",
            arn_attr="ARN"
        ))

        # ============================================================
        # Elasticsearch/OpenSearch Domains
        # ============================================================
        configs.append(ResourceConfig(
            service="OpenSearch",
            resource_type="Domain",
            client_name="opensearch",
            list_method="list_domain_names",
            list_key="DomainNames",
            id_attr="DomainName",
            arn_template=f"arn:aws:es:{self.region}:{self.account_id}:domain/{{id}}"
        ))

        # ============================================================
        # Kinesis Streams
        # ============================================================
        configs.append(ResourceConfig(
            service="Kinesis",
            resource_type="Stream",
            client_name="kinesis",
            list_method="list_streams",
            list_key="StreamNames",
            id_attr=None,
            arn_template=f"arn:aws:kinesis:{self.region}:{self.account_id}:stream/{{id}}"
        ))

        # ============================================================
        # Kinesis Firehose Delivery Streams
        # ============================================================
        configs.append(ResourceConfig(
            service="Firehose",
            resource_type="DeliveryStream",
            client_name="firehose",
            list_method="list_delivery_streams",
            list_key="DeliveryStreamNames",
            id_attr=None,
            arn_template=f"arn:aws:firehose:{self.region}:{self.account_id}:deliverystream/{{id}}"
        ))

        # ============================================================
        # CloudWatch Log Groups
        # ============================================================
        configs.append(ResourceConfig(
            service="Logs",
            resource_type="LogGroup",
            client_name="logs",
            list_method="describe_log_groups",
            list_key="logGroups",
            id_attr="logGroupName",
            arn_attr="arn"
        ))

        # ============================================================
        # CloudWatch Alarms
        # ============================================================
        configs.append(ResourceConfig(
            service="CloudWatch",
            resource_type="Alarm",
            client_name="cloudwatch",
            list_method="describe_alarms",
            list_key="MetricAlarms",
            id_attr="AlarmName",
            arn_attr="AlarmArn"
        ))

        # ============================================================
        # Secrets Manager Secrets
        # ============================================================
        configs.append(ResourceConfig(
            service="SecretsManager",
            resource_type="Secret",
            client_name="secretsmanager",
            list_method="list_secrets",
            list_key="SecretList",
            id_attr="Name",
            arn_attr="ARN"
        ))

        # ============================================================
        # SSM Parameters
        # ============================================================
        configs.append(ResourceConfig(
            service="SSM",
            resource_type="Parameter",
            client_name="ssm",
            list_method="describe_parameters",
            list_key="Parameters",
            id_attr="Name",
            arn_template=f"arn:aws:ssm:{self.region}:{self.account_id}:parameter/{{id}}"
        ))

        # ============================================================
        # KMS Keys
        # ============================================================
        configs.append(ResourceConfig(
            service="KMS",
            resource_type="Key",
            client_name="kms",
            list_method="list_keys",
            list_key="Keys",
            id_attr="KeyId",
            arn_attr="KeyArn"
        ))

        # ============================================================
        # ACM Certificates
        # ============================================================
        configs.append(ResourceConfig(
            service="ACM",
            resource_type="Certificate",
            client_name="acm",
            list_method="list_certificates",
            list_key="CertificateSummaryList",
            id_attr="DomainName",
            arn_attr="CertificateArn"
        ))

        # ============================================================
        # API Gateway REST APIs
        # ============================================================
        configs.append(ResourceConfig(
            service="APIGateway",
            resource_type="RestApi",
            client_name="apigateway",
            list_method="get_rest_apis",
            list_key="items",
            id_attr="id",
            arn_template=f"arn:aws:apigateway:{self.region}::/restapis/{{id}}"
        ))

        # ============================================================
        # API Gateway V2 (HTTP/WebSocket APIs)
        # ============================================================
        configs.append(ResourceConfig(
            service="ApiGatewayV2",
            resource_type="Api",
            client_name="apigatewayv2",
            list_method="get_apis",
            list_key="Items",
            id_attr="ApiId",
            arn_template=f"arn:aws:apigateway:{self.region}::/apis/{{id}}"
        ))

        # ============================================================
        # Step Functions State Machines
        # ============================================================
        configs.append(ResourceConfig(
            service="StepFunctions",
            resource_type="StateMachine",
            client_name="stepfunctions",
            list_method="list_state_machines",
            list_key="stateMachines",
            id_attr="name",
            arn_attr="stateMachineArn"
        ))

        # ============================================================
        # EventBridge Rules
        # ============================================================
        configs.append(ResourceConfig(
            service="Events",
            resource_type="Rule",
            client_name="events",
            list_method="list_rules",
            list_key="Rules",
            id_attr="Name",
            arn_attr="Arn"
        ))

        # ============================================================
        # Glue Resources
        # ============================================================
        configs.append(ResourceConfig(
            service="Glue",
            resource_type="Database",
            client_name="glue",
            list_method="get_databases",
            list_key="DatabaseList",
            id_attr="Name",
            arn_template=f"arn:aws:glue:{self.region}:{self.account_id}:database/{{id}}"
        ))
        configs.append(ResourceConfig(
            service="Glue",
            resource_type="Crawler",
            client_name="glue",
            list_method="get_crawlers",
            list_key="Crawlers",
            id_attr="Name",
            arn_template=f"arn:aws:glue:{self.region}:{self.account_id}:crawler/{{id}}"
        ))
        configs.append(ResourceConfig(
            service="Glue",
            resource_type="Job",
            client_name="glue",
            list_method="get_jobs",
            list_key="Jobs",
            id_attr="Name",
            arn_template=f"arn:aws:glue:{self.region}:{self.account_id}:job/{{id}}"
        ))

        # ============================================================
        # Athena Resources
        # ============================================================
        configs.append(ResourceConfig(
            service="Athena",
            resource_type="WorkGroup",
            client_name="athena",
            list_method="list_work_groups",
            list_key="WorkGroups",
            id_attr="Name",
            arn_template=f"arn:aws:athena:{self.region}:{self.account_id}:workgroup/{{id}}"
        ))

        # ============================================================
        # Redshift Clusters
        # ============================================================
        configs.append(ResourceConfig(
            service="Redshift",
            resource_type="Cluster",
            client_name="redshift",
            list_method="describe_clusters",
            list_key="Clusters",
            id_attr="ClusterIdentifier",
            arn_template=f"arn:aws:redshift:{self.region}:{self.account_id}:cluster:{{id}}"
        ))

        # ============================================================
        # EMR Clusters
        # ============================================================
        configs.append(ResourceConfig(
            service="EMR",
            resource_type="Cluster",
            client_name="emr",
            list_method="list_clusters",
            list_key="Clusters",
            id_attr="Id",
            arn_template=f"arn:aws:elasticmapreduce:{self.region}:{self.account_id}:cluster/{{id}}"
        ))

        # ============================================================
        # SageMaker Resources
        # ============================================================
        configs.append(ResourceConfig(
            service="SageMaker",
            resource_type="NotebookInstance",
            client_name="sagemaker",
            list_method="list_notebook_instances",
            list_key="NotebookInstances",
            id_attr="NotebookInstanceName",
            arn_attr="NotebookInstanceArn"
        ))
        configs.append(ResourceConfig(
            service="SageMaker",
            resource_type="Endpoint",
            client_name="sagemaker",
            list_method="list_endpoints",
            list_key="Endpoints",
            id_attr="EndpointName",
            arn_attr="EndpointArn"
        ))
        configs.append(ResourceConfig(
            service="SageMaker",
            resource_type="Model",
            client_name="sagemaker",
            list_method="list_models",
            list_key="Models",
            id_attr="ModelName",
            arn_attr="ModelArn"
        ))

        # ============================================================
        # CodeBuild Projects
        # ============================================================
        configs.append(ResourceConfig(
            service="CodeBuild",
            resource_type="Project",
            client_name="codebuild",
            list_method="list_projects",
            list_key="projects",
            id_attr=None,
            arn_template=f"arn:aws:codebuild:{self.region}:{self.account_id}:project/{{id}}"
        ))

        # ============================================================
        # CodePipeline Pipelines
        # ============================================================
        configs.append(ResourceConfig(
            service="CodePipeline",
            resource_type="Pipeline",
            client_name="codepipeline",
            list_method="list_pipelines",
            list_key="pipelines",
            id_attr="name",
            arn_template=f"arn:aws:codepipeline:{self.region}:{self.account_id}:{{id}}"
        ))

        # ============================================================
        # CodeCommit Repositories
        # ============================================================
        configs.append(ResourceConfig(
            service="CodeCommit",
            resource_type="Repository",
            client_name="codecommit",
            list_method="list_repositories",
            list_key="repositories",
            id_attr="repositoryName",
            arn_template=f"arn:aws:codecommit:{self.region}:{self.account_id}:{{id}}"
        ))

        # ============================================================
        # ECR Repositories
        # ============================================================
        configs.append(ResourceConfig(
            service="ECR",
            resource_type="Repository",
            client_name="ecr",
            list_method="describe_repositories",
            list_key="repositories",
            id_attr="repositoryName",
            arn_attr="repositoryArn"
        ))

        # ============================================================
        # ELB (Classic Load Balancers)
        # ============================================================
        configs.append(ResourceConfig(
            service="ELB",
            resource_type="LoadBalancer",
            client_name="elb",
            list_method="describe_load_balancers",
            list_key="LoadBalancerDescriptions",
            id_attr="LoadBalancerName",
            arn_template=f"arn:aws:elasticloadbalancing:{self.region}:{self.account_id}:loadbalancer/{{id}}"
        ))

        # ============================================================
        # ELBv2 (ALB/NLB)
        # ============================================================
        configs.append(ResourceConfig(
            service="ELBv2",
            resource_type="LoadBalancer",
            client_name="elbv2",
            list_method="describe_load_balancers",
            list_key="LoadBalancers",
            id_attr="LoadBalancerName",
            arn_attr="LoadBalancerArn"
        ))
        configs.append(ResourceConfig(
            service="ELBv2",
            resource_type="TargetGroup",
            client_name="elbv2",
            list_method="describe_target_groups",
            list_key="TargetGroups",
            id_attr="TargetGroupName",
            arn_attr="TargetGroupArn"
        ))

        # ============================================================
        # Auto Scaling Groups
        # ============================================================
        configs.append(ResourceConfig(
            service="AutoScaling",
            resource_type="AutoScalingGroup",
            client_name="autoscaling",
            list_method="describe_auto_scaling_groups",
            list_key="AutoScalingGroups",
            id_attr="AutoScalingGroupName",
            arn_attr="AutoScalingGroupARN"
        ))
        configs.append(ResourceConfig(
            service="AutoScaling",
            resource_type="LaunchConfiguration",
            client_name="autoscaling",
            list_method="describe_launch_configurations",
            list_key="LaunchConfigurations",
            id_attr="LaunchConfigurationName",
            arn_attr="LaunchConfigurationARN"
        ))

        # ============================================================
        # CloudFormation Stacks
        # ============================================================
        configs.append(ResourceConfig(
            service="CloudFormation",
            resource_type="Stack",
            client_name="cloudformation",
            list_method="describe_stacks",
            list_key="Stacks",
            id_attr="StackName",
            arn_attr="StackId"
        ))

        # ============================================================
        # IAM Resources (global)
        # ============================================================
        configs.append(ResourceConfig(
            service="IAM",
            resource_type="Role",
            client_name="iam",
            list_method="list_roles",
            list_key="Roles",
            id_attr="RoleName",
            arn_attr="Arn"
        ))
        configs.append(ResourceConfig(
            service="IAM",
            resource_type="User",
            client_name="iam",
            list_method="list_users",
            list_key="Users",
            id_attr="UserName",
            arn_attr="Arn"
        ))
        configs.append(ResourceConfig(
            service="IAM",
            resource_type="Policy",
            client_name="iam",
            list_method="list_policies",
            list_key="Policies",
            id_attr="PolicyName",
            arn_attr="Arn",
            list_kwargs={"Scope": "Local"}  # Only customer-managed policies
        ))

        # ============================================================
        # Route53 Hosted Zones (global)
        # ============================================================
        configs.append(ResourceConfig(
            service="Route53",
            resource_type="HostedZone",
            client_name="route53",
            list_method="list_hosted_zones",
            list_key="HostedZones",
            id_attr="Id",
            arn_template="arn:aws:route53:::hostedzone/{id}"
        ))

        # ============================================================
        # CloudFront Distributions (global)
        # ============================================================
        configs.append(ResourceConfig(
            service="CloudFront",
            resource_type="Distribution",
            client_name="cloudfront",
            list_method="list_distributions",
            list_key="DistributionList",
            id_attr="Id",
            nested_key="Items",
            arn_template="arn:aws:cloudfront::{account}:distribution/{id}"
        ))

        # ============================================================
        # WAFv2 Web ACLs
        # ============================================================
        configs.append(ResourceConfig(
            service="WAFv2",
            resource_type="WebACL",
            client_name="wafv2",
            list_method="list_web_acls",
            list_key="WebACLs",
            id_attr="Name",
            arn_attr="ARN",
            list_kwargs={"Scope": "REGIONAL"}
        ))

        # ============================================================
        # Backup Plans
        # ============================================================
        configs.append(ResourceConfig(
            service="Backup",
            resource_type="BackupPlan",
            client_name="backup",
            list_method="list_backup_plans",
            list_key="BackupPlansList",
            id_attr="BackupPlanName",
            arn_attr="BackupPlanArn"
        ))

        # ============================================================
        # EFS File Systems
        # ============================================================
        configs.append(ResourceConfig(
            service="EFS",
            resource_type="FileSystem",
            client_name="efs",
            list_method="describe_file_systems",
            list_key="FileSystems",
            id_attr="FileSystemId",
            arn_template=f"arn:aws:elasticfilesystem:{self.region}:{self.account_id}:file-system/{{id}}"
        ))

        # ============================================================
        # FSx File Systems
        # ============================================================
        configs.append(ResourceConfig(
            service="FSx",
            resource_type="FileSystem",
            client_name="fsx",
            list_method="describe_file_systems",
            list_key="FileSystems",
            id_attr="FileSystemId",
            arn_attr="ResourceARN"
        ))

        # ============================================================
        # AppSync APIs
        # ============================================================
        configs.append(ResourceConfig(
            service="AppSync",
            resource_type="GraphqlApi",
            client_name="appsync",
            list_method="list_graphql_apis",
            list_key="graphqlApis",
            id_attr="name",
            arn_attr="arn"
        ))

        # ============================================================
        # Cognito User Pools
        # ============================================================
        configs.append(ResourceConfig(
            service="CognitoIdp",
            resource_type="UserPool",
            client_name="cognito-idp",
            list_method="list_user_pools",
            list_key="UserPools",
            id_attr="Id",
            list_kwargs={"MaxResults": 60},
            arn_template=f"arn:aws:cognito-idp:{self.region}:{self.account_id}:userpool/{{id}}"
        ))

        # ============================================================
        # Cognito Identity Pools
        # ============================================================
        configs.append(ResourceConfig(
            service="CognitoIdentity",
            resource_type="IdentityPool",
            client_name="cognito-identity",
            list_method="list_identity_pools",
            list_key="IdentityPools",
            id_attr="IdentityPoolId",
            list_kwargs={"MaxResults": 60},
            arn_template=f"arn:aws:cognito-identity:{self.region}:{self.account_id}:identitypool/{{id}}"
        ))

        # ============================================================
        # Batch Resources
        # ============================================================
        configs.append(ResourceConfig(
            service="Batch",
            resource_type="ComputeEnvironment",
            client_name="batch",
            list_method="describe_compute_environments",
            list_key="computeEnvironments",
            id_attr="computeEnvironmentName",
            arn_attr="computeEnvironmentArn"
        ))
        configs.append(ResourceConfig(
            service="Batch",
            resource_type="JobQueue",
            client_name="batch",
            list_method="describe_job_queues",
            list_key="jobQueues",
            id_attr="jobQueueName",
            arn_attr="jobQueueArn"
        ))

        # ============================================================
        # MediaConvert Queues
        # ============================================================
        configs.append(ResourceConfig(
            service="MediaConvert",
            resource_type="Queue",
            client_name="mediaconvert",
            list_method="list_queues",
            list_key="Queues",
            id_attr="Name",
            arn_attr="Arn"
        ))

        # ============================================================
        # Transfer Family Servers
        # ============================================================
        configs.append(ResourceConfig(
            service="Transfer",
            resource_type="Server",
            client_name="transfer",
            list_method="list_servers",
            list_key="Servers",
            id_attr="ServerId",
            arn_attr="Arn"
        ))

        return configs

    def _list_resources(self, config: ResourceConfig) -> list[tuple[str, str]]:
        """List resources and return list of (identifier, arn) tuples."""
        try:
            client = self.session.client(config.client_name)
        except Exception as e:
            print(f"    Could not create client for {config.client_name}: {e}")
            return []

        resources = []
        try:
            list_method = getattr(client, config.list_method)
            kwargs = config.list_kwargs or {}

            # Try pagination first
            try:
                paginator = client.get_paginator(config.list_method)
                pages = paginator.paginate(**kwargs)
                for page in pages:
                    items = page.get(config.list_key, [])
                    if config.nested_key:
                        items = items.get(config.nested_key, []) if isinstance(items, dict) else items
                    resources.extend(self._extract_resources(items, config))
            except OperationNotPageableError:
                # Fall back to single call
                response = list_method(**kwargs)
                items = response.get(config.list_key, [])
                if config.nested_key:
                    items = items.get(config.nested_key, []) if isinstance(items, dict) else items
                resources.extend(self._extract_resources(items, config))
            except Exception as e:
                # Some methods don't support pagination, try direct call
                response = list_method(**kwargs)
                items = response.get(config.list_key, [])
                if config.nested_key:
                    items = items.get(config.nested_key, []) if isinstance(items, dict) else items
                resources.extend(self._extract_resources(items, config))

        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "")
            if error_code in ["AccessDeniedException", "UnauthorizedOperation"]:
                print(f"    Access denied for {config.service}:{config.resource_type}")
            else:
                print(f"    Error listing {config.service}:{config.resource_type}: {e}")
        except Exception as e:
            print(f"    Error listing {config.service}:{config.resource_type}: {e}")

        return resources

    def _extract_resources(self, items: list, config: ResourceConfig) -> list[tuple[str, str]]:
        """Extract (identifier, arn) tuples from list response."""
        resources = []

        for item in items:
            # Handle different response formats
            if isinstance(item, str):
                # Item is the identifier itself (e.g., table names, stream names)
                identifier = item
                if config.arn_template:
                    # Handle special case for Route53 hosted zone IDs
                    clean_id = identifier.replace("/hostedzone/", "") if "/hostedzone/" in identifier else identifier
                    arn = config.arn_template.format(id=clean_id, account=self.account_id)
                else:
                    arn = identifier
            elif isinstance(item, dict):
                # Item is a dict with attributes
                if config.id_attr:
                    identifier = item.get(config.id_attr)
                else:
                    identifier = None

                if config.arn_attr:
                    arn = item.get(config.arn_attr)
                elif config.arn_template and identifier:
                    arn = config.arn_template.format(id=identifier, account=self.account_id)
                else:
                    arn = None

                # For SNS topics, the ARN is also the identifier
                if config.service == "SNS" and config.resource_type == "Topic":
                    identifier = arn.split(":")[-1] if arn else None
            else:
                continue

            if identifier and arn:
                resources.append((identifier, arn))
            elif arn:
                # Extract identifier from ARN
                identifier = arn.split("/")[-1] if "/" in arn else arn.split(":")[-1]
                resources.append((identifier, arn))

        return resources

    def _tag_resource(self, arn: str, identifier: str, config: ResourceConfig) -> bool:
        """Tag a single resource. Returns True on success."""
        if self.dry_run:
            print(f"    [DRY-RUN] Would tag {identifier} with {self.tag_key}={identifier}")
            return True

        try:
            # Try Resource Groups Tagging API first (works for most services)
            self.tagging_client.tag_resources(
                ResourceARNList=[arn],
                Tags={self.tag_key: identifier}
            )
            print(f"    Tagged {identifier}")
            return True
        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "")

            # Try service-specific tagging as fallback
            if error_code in ["InvalidParameterException", "InternalServiceException"]:
                return self._tag_resource_fallback(arn, identifier, config)

            print(f"    Error tagging {identifier}: {e}")
            return False

    def _tag_resource_fallback(self, arn: str, identifier: str, config: ResourceConfig) -> bool:
        """Fallback to service-specific tagging APIs."""
        try:
            client = self.session.client(config.client_name)

            # S3 special handling
            if config.service == "S3":
                try:
                    existing = client.get_bucket_tagging(Bucket=identifier)
                    tags = existing.get("TagSet", [])
                except ClientError:
                    tags = []
                tags = [t for t in tags if t["Key"] != self.tag_key]
                tags.append({"Key": self.tag_key, "Value": identifier})
                client.put_bucket_tagging(Bucket=identifier, Tagging={"TagSet": tags})
                print(f"    Tagged {identifier} (S3 API)")
                return True

            # EC2 special handling
            elif config.service == "EC2":
                resource_id = identifier
                client.create_tags(
                    Resources=[resource_id],
                    Tags=[{"Key": self.tag_key, "Value": identifier}]
                )
                print(f"    Tagged {identifier} (EC2 API)")
                return True

            # IAM special handling
            elif config.service == "IAM":
                if config.resource_type == "Role":
                    client.tag_role(RoleName=identifier, Tags=[{"Key": self.tag_key, "Value": identifier}])
                elif config.resource_type == "User":
                    client.tag_user(UserName=identifier, Tags=[{"Key": self.tag_key, "Value": identifier}])
                elif config.resource_type == "Policy":
                    client.tag_policy(PolicyArn=arn, Tags=[{"Key": self.tag_key, "Value": identifier}])
                print(f"    Tagged {identifier} (IAM API)")
                return True

            # RDS special handling
            elif config.service == "RDS":
                client.add_tags_to_resource(
                    ResourceName=arn,
                    Tags=[{"Key": self.tag_key, "Value": identifier}]
                )
                print(f"    Tagged {identifier} (RDS API)")
                return True

            # Lambda special handling
            elif config.service == "Lambda":
                client.tag_resource(Resource=arn, Tags={self.tag_key: identifier})
                print(f"    Tagged {identifier} (Lambda API)")
                return True

            # DynamoDB special handling
            elif config.service == "DynamoDB":
                client.tag_resource(ResourceArn=arn, Tags=[{"Key": self.tag_key, "Value": identifier}])
                print(f"    Tagged {identifier} (DynamoDB API)")
                return True

            # ECS special handling
            elif config.service == "ECS":
                client.tag_resource(resourceArn=arn, tags=[{"key": self.tag_key, "value": identifier}])
                print(f"    Tagged {identifier} (ECS API)")
                return True

            # Default: try tag_resource with common patterns
            else:
                try:
                    client.tag_resource(ResourceArn=arn, Tags=[{"Key": self.tag_key, "Value": identifier}])
                    print(f"    Tagged {identifier} (fallback API)")
                    return True
                except:
                    try:
                        client.tag_resource(resourceArn=arn, tags=[{"key": self.tag_key, "value": identifier}])
                        print(f"    Tagged {identifier} (fallback API v2)")
                        return True
                    except:
                        pass

        except Exception as e:
            print(f"    Fallback tagging failed for {identifier}: {e}")

        return False

    def tag_service(self, service: str):
        """Tag all resources for a specific service."""
        configs = [c for c in self.resource_configs if c.service == service]

        if not configs:
            print(f"  Service {service} not supported")
            self.skipped_count += 1
            return

        for config in configs:
            print(f"  {config.resource_type}...")
            resources = self._list_resources(config)

            if not resources:
                print(f"    No resources found")
                continue

            for identifier, arn in resources:
                if self._tag_resource(arn, identifier, config):
                    self.tagged_count += 1
                else:
                    self.error_count += 1

    def run(self, services: list = None):
        """Run the tagging process."""
        all_services = sorted(set(c.service for c in self.resource_configs))

        if services:
            target_services = [s for s in services if s in all_services]
            unknown = [s for s in services if s not in all_services]
            if unknown:
                print(f"Unknown services: {', '.join(unknown)}")
                print(f"Available services: {', '.join(all_services)}")
        else:
            target_services = all_services

        print(f"Tag key: {self.tag_key}")
        print(f"Region: {self.region}")
        print(f"Dry run: {self.dry_run}")
        print(f"Services: {len(target_services)}")
        print("=" * 60)

        for service in target_services:
            print(f"\n{service}:")
            self.tag_service(service)

        print("\n" + "=" * 60)
        print("Summary:")
        print(f"  Tagged: {self.tagged_count}")
        print(f"  Errors: {self.error_count}")
        print(f"  Skipped: {self.skipped_count}")

    def list_supported_services(self):
        """List all supported services and resource types."""
        services = {}
        for config in self.resource_configs:
            if config.service not in services:
                services[config.service] = []
            services[config.service].append(config.resource_type)

        print("Supported services and resource types:")
        print("=" * 60)
        for service in sorted(services.keys()):
            print(f"\n{service}:")
            for res_type in sorted(services[service]):
                print(f"  - {res_type}")
        print(f"\nTotal: {len(services)} services, {len(self.resource_configs)} resource types")


def main():
    parser = argparse.ArgumentParser(
        description="Tag all taggable AWS resources with their primary identifier"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be tagged without making changes"
    )
    parser.add_argument(
        "--service",
        action="append",
        dest="services",
        help="Specific service(s) to tag (can be repeated)"
    )
    parser.add_argument(
        "--region",
        default=os.environ.get("AWS_DEFAULT_REGION", "us-east-1"),
        help="AWS region (default: us-east-1 or AWS_DEFAULT_REGION)"
    )
    parser.add_argument(
        "--list-services",
        action="store_true",
        help="List all supported services and exit"
    )

    args = parser.parse_args()

    # --list-services doesn't need credentials or tag key
    if args.list_services:
        # Create a minimal config list without AWS calls
        print("Supported services and resource types:")
        print("=" * 60)
        services = {
            "ACM": ["Certificate"],
            "APIGateway": ["RestApi"],
            "ApiGatewayV2": ["Api"],
            "AppSync": ["GraphqlApi"],
            "Athena": ["WorkGroup"],
            "AutoScaling": ["AutoScalingGroup", "LaunchConfiguration"],
            "Backup": ["BackupPlan"],
            "Batch": ["ComputeEnvironment", "JobQueue"],
            "CloudFormation": ["Stack"],
            "CloudFront": ["Distribution"],
            "CloudWatch": ["Alarm"],
            "CodeBuild": ["Project"],
            "CodeCommit": ["Repository"],
            "CodePipeline": ["Pipeline"],
            "CognitoIdentity": ["IdentityPool"],
            "CognitoIdp": ["UserPool"],
            "DynamoDB": ["Table"],
            "EC2": ["Instance", "Volume", "Snapshot", "SecurityGroup", "Subnet", "VPC",
                    "InternetGateway", "NatGateway", "NetworkInterface", "RouteTable",
                    "NetworkAcl", "VpcEndpoint", "VpnGateway", "CustomerGateway",
                    "DhcpOptions", "EgressOnlyInternetGateway", "ElasticIp", "FlowLog",
                    "KeyPair", "LaunchTemplate", "PlacementGroup", "PrefixList",
                    "TransitGateway", "TransitGatewayAttachment", "TransitGatewayRouteTable", "Image"],
            "ECR": ["Repository"],
            "ECS": ["Cluster"],
            "EFS": ["FileSystem"],
            "EKS": ["Cluster"],
            "ELB": ["LoadBalancer"],
            "ELBv2": ["LoadBalancer", "TargetGroup"],
            "ElastiCache": ["CacheCluster", "ReplicationGroup"],
            "EMR": ["Cluster"],
            "Events": ["Rule"],
            "Firehose": ["DeliveryStream"],
            "FSx": ["FileSystem"],
            "Glue": ["Database", "Crawler", "Job"],
            "IAM": ["Role", "User", "Policy"],
            "KMS": ["Key"],
            "Kinesis": ["Stream"],
            "Lambda": ["Function"],
            "Logs": ["LogGroup"],
            "MediaConvert": ["Queue"],
            "OpenSearch": ["Domain"],
            "RDS": ["DBInstance", "DBCluster", "DBSnapshot", "DBClusterSnapshot",
                    "DBSubnetGroup", "DBParameterGroup", "OptionGroup"],
            "Redshift": ["Cluster"],
            "Route53": ["HostedZone"],
            "S3": ["Bucket"],
            "SNS": ["Topic"],
            "SQS": ["Queue"],
            "SSM": ["Parameter"],
            "SageMaker": ["NotebookInstance", "Endpoint", "Model"],
            "SecretsManager": ["Secret"],
            "StepFunctions": ["StateMachine"],
            "Transfer": ["Server"],
            "WAFv2": ["WebACL"],
        }
        total_resources = 0
        for service in sorted(services.keys()):
            print(f"\n{service}:")
            for res_type in sorted(services[service]):
                print(f"  - {res_type}")
                total_resources += 1
        print(f"\nTotal: {len(services)} services, {total_resources} resource types")
        return

    try:
        tagger = ResourceTagger(region=args.region, dry_run=args.dry_run)
        tagger.run(services=args.services)

    except NoCredentialsError:
        print("Error: AWS credentials not found")
        print("Configure via environment variables, ~/.aws/credentials, or IAM role")
        sys.exit(1)


if __name__ == "__main__":
    main()
