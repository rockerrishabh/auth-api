use crate::{
    db::{
        models::{NewSystemSetting, SystemSetting},
        DbPool,
    },
    error::{AuthError, AuthResult},
};
use diesel::prelude::*;
use std::collections::HashMap;
use chrono::Utc;

pub struct SystemService {
    pool: DbPool,
}

impl SystemService {
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }

    /// Get a system setting by key
    pub async fn get_setting(&self, key: &str) -> AuthResult<Option<SystemSetting>> {
        use crate::db::schemas::system_settings::dsl::*;

        let mut conn = self.pool.get().map_err(|e| AuthError::DatabaseError(e.to_string()))?;

        let result = system_settings
            .filter(setting_key.eq(key))
            .first::<SystemSetting>(&mut conn)
            .optional()
            .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

        Ok(result)
    }

    /// Set a system setting (creates or updates)
    pub async fn set_setting(&self, key: &str, value: &str, setting_type_param: &str, description_param: Option<&str>) -> AuthResult<SystemSetting> {
        use crate::db::schemas::system_settings::dsl::*;

        let mut conn = self.pool.get().map_err(|e| AuthError::DatabaseError(e.to_string()))?;

        // Try to update existing setting
        let update_result = diesel::update(system_settings.filter(setting_key.eq(key)))
            .set((
                setting_value.eq(value),
                setting_type.eq(setting_type_param),
                description.eq(description_param),
                updated_at.eq(Utc::now()),
            ))
            .get_result::<SystemSetting>(&mut conn)
            .optional()
            .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

        if let Some(setting) = update_result {
            return Ok(setting);
        }

        // Create new setting if it doesn't exist
        let new_setting = NewSystemSetting {
            setting_key: key,
            setting_value: value,
            setting_type: setting_type_param,
            description: description_param,
        };

        diesel::insert_into(system_settings)
            .values(&new_setting)
            .get_result::<SystemSetting>(&mut conn)
            .map_err(|e| AuthError::DatabaseError(e.to_string()))
    }

    /// Get all system settings as a HashMap
    pub async fn get_all_settings(&self) -> AuthResult<HashMap<String, String>> {
        use crate::db::schemas::system_settings::dsl::*;

        let mut conn = self.pool.get().map_err(|e| AuthError::DatabaseError(e.to_string()))?;

        let settings = system_settings
            .load::<SystemSetting>(&mut conn)
            .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

        let mut result = HashMap::new();
        for setting in settings {
            result.insert(setting.setting_key, setting.setting_value);
        }

        Ok(result)
    }

    /// Initialize default system settings
    pub async fn initialize_defaults(&self) -> AuthResult<()> {
        let defaults = vec![
            ("app_name", "Advanced Authentication System", "string", Some("Application name displayed to users")),
            ("app_description", "Advanced Authentication System", "string", Some("Application description")),
            ("maintenance_mode", "false", "boolean", Some("Whether the system is in maintenance mode")),
            ("registration_enabled", "true", "boolean", Some("Whether new user registration is allowed")),
            ("email_verification_required", "true", "boolean", Some("Whether email verification is required")),
            ("two_factor_required", "false", "boolean", Some("Whether 2FA is required for all users")),
        ];

        for (key, value, setting_type, description) in defaults {
            self.set_setting(key, value, setting_type, description).await?;
        }

        Ok(())
    }

    /// Get a boolean setting with default fallback
    pub async fn get_bool_setting(&self, key: &str, default: bool) -> AuthResult<bool> {
        match self.get_setting(key).await? {
            Some(setting) => {
                setting.setting_value.parse::<bool>()
                    .map_err(|_| AuthError::ValidationFailed(format!("Invalid boolean value for setting: {}", key)))
            },
            None => Ok(default)
        }
    }

    /// Get a string setting with default fallback
    pub async fn get_string_setting(&self, key: &str, default: &str) -> AuthResult<String> {
        match self.get_setting(key).await? {
            Some(setting) => Ok(setting.setting_value),
            None => Ok(default.to_string())
        }
    }
}
