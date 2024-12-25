use aliyun_openapi_core_rust_sdk::client::rpc::RPClient;
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::sync::RwLock;
use std::time::Duration;

type KmsResult<T> = Result<T, Box<dyn Error>>;

const DEFAULT_TIMEOUT_SECS: u64 = 5;
const DEFAULT_KMS_API_VERSION: &str = "2016-01-20";

const ENV_KMS_ACCESS_KEY_ID: &str = "KMS_ACCESS_KEY_ID";
const ENV_KMS_ACCESS_KEY_SECRET: &str = "KMS_ACCESS_KEY_SECRET";
const ENV_KMS_SECURITY_TOKEN: &str = "KMS_SECURITY_TOKEN";
const ENV_KMS_ECS_RAM_ROLE: &str = "KMS_ECS_RAM_ROLE";

#[derive(Default, Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct GetSecretValueRequest {
    pub secret_name: String,
    pub version_stage: Option<String>,
    pub version_id: Option<String>,
    pub fetch_extended_config: Option<bool>,
    pub dry_run: Option<bool>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct GetSecretValueResponse {
    pub request_id: String,
    pub secret_data_type: String,
    pub create_time: String,
    pub version_id: String,
    pub next_rotation_date: Option<String>,
    pub secret_data: String,
    pub rotation_interval: Option<String>,
    pub extended_config: Option<String>,
    pub last_rotation_date: Option<String>,
    pub secret_name: String,
    pub automatic_rotation: Option<String>,
    pub secret_type: String,
    pub version_stages: GetSecretValueVersionStages,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct GetSecretValueVersionStages {
    pub version_stage: Vec<String>,
}

#[derive(Default, Debug, Clone)]
pub struct KmsClient {
    pub endpoint: Option<String>,
    pub timeout: Option<Duration>,
    pub credential_config: CredentialConfig,
}

impl KmsClient {
    pub fn new(credential_config: CredentialConfig) -> Self {
        Self {
            credential_config,
            ..Default::default()
        }
    }

    pub fn endpoint(mut self, endpoint: impl Into<String>) -> Self {
        let endpoint = endpoint.into();
        if endpoint.starts_with("kms") {
            self.endpoint = Some(format!("https://{}", endpoint));
        } else {
            self.endpoint = Some(endpoint);
        }
        self
    }

    // Err(
    //     InvalidResponse {
    //         request_id: "d58029b6-f90e-4dcd-9d75-0aeabf4a9339",
    //         error_code: "Forbidden.ResourceNotFound",
    //         error_message: "Resource not found.",
    //     },
    // )
    // reference: https://api.aliyun.com/document/Kms/2016-01-20/GetSecretValue
    pub async fn get_secret_value(
        &self,
        request: GetSecretValueRequest,
    ) -> KmsResult<GetSecretValueResponse> {
        let (kms_client, credential_config) = self.build_rpc_client()?;
        let mut queries = vec![];
        if let Some(security_token) = &credential_config.security_token {
            queries.push(("???", security_token.as_str()));
            todo!("");
        }
        queries.push(("SecretName", request.secret_name.as_str()));
        if let Some(version_stage) = &request.version_stage {
            queries.push(("VersionStage", version_stage));
        }
        if let Some(version_id) = &request.version_id {
            queries.push(("VersionId", version_id));
        }
        if let Some(fetch_extended_config) = &request.fetch_extended_config {
            queries.push(("FetchExtendedConfig", bool_to_str(*fetch_extended_config)));
        }
        if let Some(dry_run) = &request.dry_run {
            queries.push(("DryRun", bool_to_str(*dry_run)));
        }
        let response = kms_client
            .post("GetSecretValue")
            .query(queries)
            .send()
            .await?;
        let response_text = response.text().await?;
        Ok(serde_json::from_str(&response_text).unwrap())
    }

    fn build_rpc_client(&self) -> KmsResult<(RPClient, CredentialConfig)> {
        let endpoint = match &self.endpoint {
            Some(endpoint) => endpoint,
            None => todo!(""),
        };

        let credential_config = self.credential_config.provider_credential_config();
        let (access_key_id, access_key_secret) = match (
            &credential_config.access_key_id,
            &credential_config.access_key_secret,
        ) {
            (Some(access_key_id), Some(access_key_secret)) => (access_key_id, access_key_secret),
            _ => todo!(""),
        };
        let timeout = self
            .timeout
            .unwrap_or_else(|| Duration::from_secs(DEFAULT_TIMEOUT_SECS));
        let rpc_client = RPClient::new(access_key_id, access_key_secret, endpoint)
            .timeout(timeout)
            .version(DEFAULT_KMS_API_VERSION);
        Ok((rpc_client, credential_config))
    }
}

#[derive(Default, Debug)]
pub struct CredentialConfig {
    cached_credential_config: Option<RwLock<Box<CredentialConfig>>>,

    pub access_key_id: Option<String>,
    pub access_key_secret: Option<String>,
    pub security_token: Option<String>,
    pub ecs_ram_role: Option<String>,
}

impl Clone for CredentialConfig {
    fn clone(&self) -> Self {
        Self {
            cached_credential_config: None,
            access_key_id: self.access_key_id.clone(),
            access_key_secret: self.access_key_secret.clone(),
            security_token: self.security_token.clone(),
            ecs_ram_role: self.ecs_ram_role.clone(),
        }
    }
}

impl CredentialConfig {
    pub fn new_ak(access_key_id: impl Into<String>, access_key_secret: impl Into<String>) -> Self {
        Self {
            access_key_id: Some(access_key_id.into()),
            access_key_secret: Some(access_key_secret.into()),
            ..Default::default()
        }
    }

    pub fn new_sts(
        access_key_id: impl Into<String>,
        access_key_secret: impl Into<String>,
        security_token: impl Into<String>,
    ) -> Self {
        Self {
            access_key_id: Some(access_key_id.into()),
            access_key_secret: Some(access_key_secret.into()),
            security_token: Some(security_token.into()),
            ..Default::default()
        }
    }

    pub fn new_ecs_ram_role(ecs_ram_role: impl Into<String>) -> Self {
        Self {
            ecs_ram_role: Some(ecs_ram_role.into()),
            ..Default::default()
        }
    }

    pub fn try_from_env() -> Option<Self> {
        let kms_access_key_id = std::env::var(ENV_KMS_ACCESS_KEY_ID).ok();
        let kms_access_key_secret = std::env::var(ENV_KMS_ACCESS_KEY_SECRET).ok();
        let kms_security_token = std::env::var(ENV_KMS_SECURITY_TOKEN).ok();
        if kms_access_key_id.is_some() && kms_access_key_secret.is_some() {
            return Some(Self {
                access_key_id: kms_access_key_id,
                access_key_secret: kms_access_key_secret,
                security_token: kms_security_token,
                ..Default::default()
            });
        }
        let kms_ecs_ram_role = std::env::var(ENV_KMS_ECS_RAM_ROLE).ok();
        if kms_ecs_ram_role.is_some() {
            return Some(Self {
                ecs_ram_role: kms_ecs_ram_role,
                ..Default::default()
            });
        }
        None
    }

    pub fn provider_credential_config(&self) -> Self {
        if let Some(_ecs_ram_role) = &self.ecs_ram_role {
            todo!("TOBE IMPLEMENTED.")
        } else {
            self.clone()
        }
    }
}

fn bool_to_str(b: bool) -> &'static str {
    if b {
        "true"
    } else {
        "false"
    }
}
