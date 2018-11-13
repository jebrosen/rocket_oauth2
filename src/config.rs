use rocket::config::{self, Config, ConfigError, Table, Value};

use crate::Provider;

/// Holds configuration for an OAuth application. This consists of the [Provider]
/// details, a `client_id` and `client_secret`, and a `redirect_uri`.
pub struct OAuthConfig {
    provider: Provider,
    client_id: String,
    client_secret: String,
    redirect_uri: String,
}

fn get_config_string(table: &Table, key: &str) -> config::Result<String> {
    let value = table
        .get(key)
        .ok_or_else(|| ConfigError::Missing(key.into()))?;

    let string = value
        .as_str()
        .ok_or_else(|| ConfigError::BadType(key.into(), "string", value.type_str(), None))?;

    Ok(string.to_string())
}

impl OAuthConfig {
    /// Create a new OAuthConfig.
    pub fn new(
        provider: Provider,
        client_id: String,
        client_secret: String,
        redirect_uri: String,
    ) -> OAuthConfig {
        OAuthConfig {
            provider,
            client_id,
            client_secret,
            redirect_uri,
        }
    }

    /// Constructs a OAuthConfig from Rocket configuration
    pub fn from_config(config: &Config, name: &str) -> config::Result<OAuthConfig> {
        let oauth = config.get_table("oauth")?;
        let conf = oauth
            .get(name)
            .ok_or_else(|| ConfigError::Missing(name.to_string()))?;

        let table = conf.as_table().ok_or_else(|| {
            ConfigError::BadType(name.into(), "table", conf.type_str(), None)
        })?;

        let provider = match conf.get("provider") {
            Some(v) => Provider::from_config_value(v),
            None => Err(ConfigError::Missing("provider".to_string())),
        }?;

        let client_id = get_config_string(table, "client_id")?;
        let client_secret = get_config_string(table, "client_secret")?;
        let redirect_uri = get_config_string(table, "redirect_uri")?;

        Ok(OAuthConfig::new(
            provider,
            client_id,
            client_secret,
            redirect_uri,
        ))
    }

    /// Gets the [Provider] for this configuration.
    pub fn provider(&self) -> &Provider {
        &self.provider
    }

    /// Gets the client id for this configuration.
    pub fn client_id(&self) -> &str {
        &self.client_id
    }

    /// Gets the client secret for this configuration.
    pub fn client_secret(&self) -> &str {
        &self.client_secret
    }

    /// Gets the redirect URI for this configuration.
    pub fn redirect_uri(&self) -> &str {
        &self.redirect_uri
    }
}

impl Provider {
    fn from_config_value(conf: &Value) -> Result<Provider, ConfigError> {
        let type_error = || {
            ConfigError::BadType(
                "provider".into(),
                "known provider or table",
                "",
                None,
            )
        };

        match conf {
            Value::String(s) => Provider::from_known_name(s).ok_or_else(type_error),
            Value::Table(t) => {
                let auth_uri = get_config_string(t, "auth_uri")?.into();
                let token_uri = get_config_string(t, "token_uri")?.into();

                Ok(Provider {
                    auth_uri,
                    token_uri,
                })
            }
            _ => Err(type_error()),
        }
    }
}
