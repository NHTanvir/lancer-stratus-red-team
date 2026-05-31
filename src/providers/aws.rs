use anyhow::Result;
use aws_config::BehaviorVersion;

pub struct AwsProviders {
    pub config: aws_config::SdkConfig,
    pub iam: aws_sdk_iam::Client,
    pub sts: aws_sdk_sts::Client,
    pub ec2: aws_sdk_ec2::Client,
    pub s3: aws_sdk_s3::Client,
    pub lambda: aws_sdk_lambda::Client,
    pub secretsmanager: aws_sdk_secretsmanager::Client,
    pub ssm: aws_sdk_ssm::Client,
    pub cloudtrail: aws_sdk_cloudtrail::Client,
    pub rds: aws_sdk_rds::Client,
    pub route53: aws_sdk_route53::Client,
    pub ses: aws_sdk_sesv2::Client,
    pub organizations: aws_sdk_organizations::Client,
    pub rolesanywhere: aws_sdk_rolesanywhere::Client,
    pub bedrock: aws_sdk_bedrock::Client,
    pub bedrockruntime: aws_sdk_bedrockruntime::Client,
    pub sagemaker: aws_sdk_sagemaker::Client,
    pub ec2instanceconnect: aws_sdk_ec2instanceconnect::Client,
    pub route53resolver: aws_sdk_route53resolver::Client,
}

impl AwsProviders {
    pub async fn load() -> Result<Self> {
        let config = aws_config::load_defaults(BehaviorVersion::latest()).await;
        Ok(Self {
            iam: aws_sdk_iam::Client::new(&config),
            sts: aws_sdk_sts::Client::new(&config),
            ec2: aws_sdk_ec2::Client::new(&config),
            s3: aws_sdk_s3::Client::new(&config),
            lambda: aws_sdk_lambda::Client::new(&config),
            secretsmanager: aws_sdk_secretsmanager::Client::new(&config),
            ssm: aws_sdk_ssm::Client::new(&config),
            cloudtrail: aws_sdk_cloudtrail::Client::new(&config),
            rds: aws_sdk_rds::Client::new(&config),
            route53: aws_sdk_route53::Client::new(&config),
            ses: aws_sdk_sesv2::Client::new(&config),
            organizations: aws_sdk_organizations::Client::new(&config),
            rolesanywhere: aws_sdk_rolesanywhere::Client::new(&config),
            bedrock: aws_sdk_bedrock::Client::new(&config),
            bedrockruntime: aws_sdk_bedrockruntime::Client::new(&config),
            sagemaker: aws_sdk_sagemaker::Client::new(&config),
            ec2instanceconnect: aws_sdk_ec2instanceconnect::Client::new(&config),
            route53resolver: aws_sdk_route53resolver::Client::new(&config),
            config,
        })
    }
}
