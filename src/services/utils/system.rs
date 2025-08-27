use crate::{
    db::{
        models::{NewSystemSetting, SystemSetting},
        DbPool,
    },
    error::{AuthError, AuthResult},
};
use chrono::Utc;
use diesel::prelude::*;
use serde_json::json;
use std::collections::HashMap;
use sysinfo::System;

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

        let mut conn = self
            .pool
            .get()
            .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

        let result = system_settings
            .filter(setting_key.eq(key))
            .first::<SystemSetting>(&mut conn)
            .optional()
            .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

        Ok(result)
    }

    /// Set a system setting (creates or updates)
    pub async fn set_setting(
        &self,
        key: &str,
        value: &str,
        setting_type_param: &str,
        description_param: Option<&str>,
    ) -> AuthResult<SystemSetting> {
        use crate::db::schemas::system_settings::dsl::*;

        let mut conn = self
            .pool
            .get()
            .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

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

        let mut conn = self
            .pool
            .get()
            .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

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
            (
                "app_name",
                "Advanced Authentication System",
                "string",
                Some("Application name displayed to users"),
            ),
            (
                "app_description",
                "Advanced Authentication System",
                "string",
                Some("Application description"),
            ),
            (
                "maintenance_mode",
                "false",
                "boolean",
                Some("Whether the system is in maintenance mode"),
            ),
            (
                "registration_enabled",
                "true",
                "boolean",
                Some("Whether new user registration is allowed"),
            ),
            (
                "email_verification_required",
                "true",
                "boolean",
                Some("Whether email verification is required"),
            ),
            (
                "two_factor_required",
                "false",
                "boolean",
                Some("Whether 2FA is required for all users"),
            ),
            (
                "performance_monitoring_enabled",
                "true",
                "boolean",
                Some("Whether performance monitoring is enabled"),
            ),
            (
                "auto_cleanup_enabled",
                "true",
                "boolean",
                Some("Whether automatic cleanup of old data is enabled"),
            ),
            (
                "backup_enabled",
                "false",
                "boolean",
                Some("Whether automatic backups are enabled"),
            ),
        ];

        for (key, value, setting_type, description) in defaults {
            self.set_setting(key, value, setting_type, description)
                .await?;
        }

        Ok(())
    }

    /// Get a boolean setting with default fallback
    pub async fn get_bool_setting(&self, key: &str, default: bool) -> AuthResult<bool> {
        match self.get_setting(key).await? {
            Some(setting) => setting.setting_value.parse::<bool>().map_err(|_| {
                AuthError::ValidationFailed(format!("Invalid boolean value for setting: {}", key))
            }),
            None => Ok(default),
        }
    }

    /// Get a string setting with default fallback
    pub async fn get_string_setting(&self, key: &str, default: &str) -> AuthResult<String> {
        match self.get_setting(key).await? {
            Some(setting) => Ok(setting.setting_value),
            None => Ok(default.to_string()),
        }
    }

    /// Get real-time system health metrics
    pub async fn get_system_health_metrics(
        &self,
    ) -> AuthResult<HashMap<String, serde_json::Value>> {
        let mut sys = System::new_all();
        sys.refresh_all();

        let mut metrics = HashMap::new();

        // CPU metrics
        let cpu_usage = sys.global_cpu_usage();
        metrics.insert("cpu_usage_percent".to_string(), json!(cpu_usage));
        metrics.insert("cpu_count".to_string(), json!(sys.cpus().len()));

        // Memory metrics
        let total_memory = sys.total_memory();
        let used_memory = sys.used_memory();

        metrics.insert(
            "memory_used_mb".to_string(),
            json!(used_memory / 1024 / 1024),
        );
        metrics.insert(
            "memory_total_mb".to_string(),
            json!(total_memory / 1024 / 1024),
        );
        metrics.insert(
            "memory_usage_percent".to_string(),
            json!((used_memory as f64 / total_memory as f64) * 100.0),
        );

        // Process metrics
        let processes = sys.processes();
        metrics.insert("process_count".to_string(), json!(processes.len()));

        // Database connection health
        let db_health = match self.pool.get() {
            Ok(_) => "healthy",
            Err(_) => "unhealthy",
        };
        metrics.insert("database_status".to_string(), json!(db_health));

        Ok(metrics)
    }

    /// Check if system needs maintenance based on metrics
    pub async fn check_maintenance_needs(
        &self,
    ) -> AuthResult<Vec<HashMap<String, serde_json::Value>>> {
        let metrics = self.get_system_health_metrics().await?;
        let mut alerts = Vec::new();

        // Check CPU usage
        if let Some(cpu_usage) = metrics.get("cpu_usage_percent") {
            if let Some(usage) = cpu_usage.as_f64() {
                if usage > 90.0 {
                    alerts.push(HashMap::from([
                        ("type".to_string(), json!("critical")),
                        ("component".to_string(), json!("cpu")),
                        ("message".to_string(), json!("CPU usage is critically high")),
                        ("value".to_string(), json!(usage)),
                        ("threshold".to_string(), json!(90.0)),
                        (
                            "recommendation".to_string(),
                            json!("Check for runaway processes or consider scaling"),
                        ),
                    ]));
                } else if usage > 80.0 {
                    alerts.push(HashMap::from([
                        ("type".to_string(), json!("warning")),
                        ("component".to_string(), json!("cpu")),
                        ("message".to_string(), json!("CPU usage is high")),
                        ("value".to_string(), json!(usage)),
                        ("threshold".to_string(), json!(80.0)),
                        (
                            "recommendation".to_string(),
                            json!("Monitor CPU usage and optimize if needed"),
                        ),
                    ]));
                }
            }
        }

        // Check memory usage
        if let Some(memory_usage) = metrics.get("memory_usage_percent") {
            if let Some(usage) = memory_usage.as_f64() {
                if usage > 95.0 {
                    alerts.push(HashMap::from([
                        ("type".to_string(), json!("critical")),
                        ("component".to_string(), json!("memory")),
                        (
                            "message".to_string(),
                            json!("Memory usage is critically high"),
                        ),
                        ("value".to_string(), json!(usage)),
                        ("threshold".to_string(), json!(95.0)),
                        (
                            "recommendation".to_string(),
                            json!("Immediate action required - check for memory leaks"),
                        ),
                    ]));
                } else if usage > 85.0 {
                    alerts.push(HashMap::from([
                        ("type".to_string(), json!("warning")),
                        ("component".to_string(), json!("memory")),
                        ("message".to_string(), json!("Memory usage is high")),
                        ("value".to_string(), json!(usage)),
                        ("threshold".to_string(), json!(85.0)),
                        (
                            "recommendation".to_string(),
                            json!("Monitor memory usage and consider cleanup"),
                        ),
                    ]));
                }
            }
        }

        // Check database health
        if let Some(db_status) = metrics.get("database_status") {
            if let Some(status) = db_status.as_str() {
                if status == "unhealthy" {
                    alerts.push(HashMap::from([
                        ("type".to_string(), json!("critical")),
                        ("component".to_string(), json!("database")),
                        (
                            "message".to_string(),
                            json!("Database connection is unhealthy"),
                        ),
                        ("value".to_string(), json!(status)),
                        ("threshold".to_string(), json!("healthy")),
                        (
                            "recommendation".to_string(),
                            json!("Check database server and connection pool"),
                        ),
                    ]));
                }
            }
        }

        Ok(alerts)
    }

    /// Get system performance score (0-100)
    pub async fn get_performance_score(&self) -> AuthResult<f64> {
        let metrics = self.get_system_health_metrics().await?;
        let mut score = 100.0;

        // CPU penalty
        if let Some(cpu_usage) = metrics.get("cpu_usage_percent") {
            if let Some(usage) = cpu_usage.as_f64() {
                if usage > 80.0 {
                    score -= (usage - 80.0) * 0.5; // 0.5 points per % over 80%
                }
            }
        }

        // Memory penalty
        if let Some(memory_usage) = metrics.get("memory_usage_percent") {
            if let Some(usage) = memory_usage.as_f64() {
                if usage > 80.0 {
                    score -= (usage - 80.0) * 0.5; // 0.5 points per % over 80%
                }
            }
        }

        // Database health penalty
        if let Some(db_status) = metrics.get("database_status") {
            if let Some(status) = db_status.as_str() {
                if status == "unhealthy" {
                    score -= 20.0; // 20 point penalty for unhealthy database
                }
            }
        }

        Ok(score.max(0.0).min(100.0))
    }
}
