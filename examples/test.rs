use alibaba_cloud_kms::{CredentialConfig, GetSecretValueRequest, KmsClient};

#[tokio::main]
async fn main() {
    let confidential_config = CredentialConfig::try_from_env().unwrap();
    let kms_client = KmsClient::new(confidential_config)
        .endpoint("kms.cn-shanghai.aliyuncs.com");
    let resp = kms_client
        .get_secret_value(GetSecretValueRequest {
            secret_name: "Test".into(),
            ..Default::default()
        })
        .await;
    println!("{:#?}", resp);
}
