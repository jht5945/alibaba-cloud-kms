use alibaba_cloud_kms::{
    CredentialConfig, DescribeSecretRequest, GetSecretValueRequest, KmsClient,
};

#[tokio::main]
async fn main() {
    let endpoint = "kms.cn-hangzhou.aliyuncs.com";
    let confidential_config = CredentialConfig::try_from_default(None).unwrap().unwrap();
    let kms_client = KmsClient::new(confidential_config).endpoint(endpoint);

    // {
    //   "RequestId": "5421f2a9-1490-48bf-a53c-6f2d9d3f48e3",
    //   "SecretDataType": "text",
    //   "CreateTime": "2024-12-28T02:01:20Z",
    //   "VersionId": "v1",
    //   "NextRotationDate": null,
    //   "SecretData": "{\"a\":\"1\",\"b\":\"2\"}",
    //   "RotationInterval": null,
    //   "ExtendedConfig": null,
    //   "LastRotationDate": null,
    //   "SecretName": "Test",
    //   "AutomaticRotation": null,
    //   "SecretType": "Generic",
    //   "VersionStages": {
    //     "VersionStage": [
    //       "ACSCurrent"
    //     ]
    //   }
    // }
    let resp = kms_client
        .get_secret_value(GetSecretValueRequest {
            secret_name: "Test".into(),
            ..Default::default()
        })
        .await;
    println!("{:#?}", resp);

    // {
    //   "RequestId": "6ad518a3-1478-4032-ad0a-1fe91ed2fb6d",
    //   "UpdateTime": "2024-12-28T02:01:20Z",
    //   "CreateTime": "2024-12-28T02:01:20Z",
    //   "NextRotationDate": null,
    //   "EncryptionKeyId": null,
    //   "RotationInterval": null,
    //   "Arn": "acs:kms:cn-hangzhou:1747527333918361:secret/Test",
    //   "ExtendedConfig": null,
    //   "LastRotationDate": null,
    //   "Description": "",
    //   "SecretName": "Test",
    //   "AutomaticRotation": null,
    //   "SecretType": "Generic",
    //   "PlannedDeleteTime": null,
    //   "DKMSInstanceId": null,
    //   "Tags": null
    // }
    let resp = kms_client
        .describe_secret(DescribeSecretRequest {
            secret_name: "Test".into(),fetch_tags: Some(true),
            ..Default::default()
        })
        .await;
    println!("{:#?}", resp);
}
