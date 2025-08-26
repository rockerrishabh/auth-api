use crate::db::models::{NewUserActivityLog, UserActivityLog};
use crate::db::schemas::user_activity_logs::dsl::*;
use crate::db::DbPool;
use crate::error::{AuthError, AuthResult};
use chrono::{DateTime, Utc};
use diesel::{ExpressionMethods, QueryDsl, RunQueryDsl};
use diesel_json::Json;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize)]
pub struct ActivityLogRequest {
    pub user_id: Uuid,
    pub activity_type: String,
    pub description: String,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub metadata: Option<serde_json::Value>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ActivityLogResponse {
    pub id: Uuid,
    pub user_id: Uuid,
    pub activity_type: String,
    pub description: String,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub metadata: Option<serde_json::Value>,
    pub created_at: DateTime<Utc>,
}

#[derive(Clone)]
pub struct ActivityService {
    db_pool: DbPool,
}


impl ActivityService {
    pub fn new(db_pool: DbPool) -> Self {
        Self { db_pool }
    }

    pub async fn log_activity(
        &self,
        request: ActivityLogRequest,
    ) -> AuthResult<ActivityLogResponse> {
        let mut conn = self
            .db_pool
            .get()
            .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

        let new_activity = NewUserActivityLog {
            user_id: request.user_id,
            activity_type: request.activity_type,
            description: request.description,
            ip_address: request.ip_address,
            user_agent: request.user_agent,
            metadata: request.metadata.map(|v| Json(v)),
        };

        let inserted_activity = diesel::insert_into(user_activity_logs)
            .values(&new_activity)
            .get_result::<UserActivityLog>(&mut conn)?;

        Ok(inserted_activity.into())
    }

    pub async fn get_user_activities(
        &self,
        target_user_id: Uuid,
        limit: Option<i64>,
    ) -> AuthResult<Vec<ActivityLogResponse>> {
        let mut conn = self
            .db_pool
            .get()
            .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

        let mut query = user_activity_logs
            .filter(user_id.eq(&target_user_id))
            .order(created_at.desc())
            .into_boxed();

        if let Some(limit_val) = limit {
            query = query.limit(limit_val);
        }

        let activities = query.load::<UserActivityLog>(&mut conn)?;
        Ok(activities.into_iter().map(|a| a.into()).collect())
    }

    pub async fn get_recent_activities(&self, limit: i64) -> AuthResult<Vec<ActivityLogResponse>> {
        let mut conn = self
            .db_pool
            .get()
            .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

        let activities = user_activity_logs
            .order(created_at.desc())
            .limit(limit)
            .load::<UserActivityLog>(&mut conn)?;

        Ok(activities.into_iter().map(|a| a.into()).collect())
    }

    /// Get total logins today
    pub async fn get_total_logins_today(&self) -> AuthResult<i64> {
        let mut conn = self
            .db_pool
            .get()
            .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

        let today = Utc::now().date_naive();
        let count = user_activity_logs
            .filter(activity_type.eq("login"))
            .filter(created_at.ge(today.and_hms_opt(0, 0, 0).unwrap().and_utc()))
            .filter(created_at.lt(today.and_hms_opt(23, 59, 59).unwrap().and_utc()))
            .count()
            .get_result::<i64>(&mut conn)?;

        Ok(count)
    }

    /// Get total logins this week
    pub async fn get_total_logins_week(&self) -> AuthResult<i64> {
        let mut conn = self
            .db_pool
            .get()
            .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

        let week_ago = Utc::now() - chrono::Duration::days(7);
        let count = user_activity_logs
            .filter(activity_type.eq("login"))
            .filter(created_at.ge(week_ago))
            .count()
            .get_result::<i64>(&mut conn)?;

        Ok(count)
    }

    /// Get total logins this month
    pub async fn get_total_logins_month(&self) -> AuthResult<i64> {
        let mut conn = self
            .db_pool
            .get()
            .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

        let month_ago = Utc::now() - chrono::Duration::days(30);
        let count = user_activity_logs
            .filter(activity_type.eq("login"))
            .filter(created_at.ge(month_ago))
            .count()
            .get_result::<i64>(&mut conn)?;

        Ok(count)
    }

    /// Get failed login attempts
    pub async fn get_failed_login_attempts(&self) -> AuthResult<i64> {
        let mut conn = self
            .db_pool
            .get()
            .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

        let count = user_activity_logs
            .filter(activity_type.eq("failed_login"))
            .count()
            .get_result::<i64>(&mut conn)?;

        Ok(count)
    }

    /// Get password reset requests
    pub async fn get_password_reset_requests(&self) -> AuthResult<i64> {
        let mut conn = self
            .db_pool
            .get()
            .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

        let count = user_activity_logs
            .filter(activity_type.eq("password_reset"))
            .count()
            .get_result::<i64>(&mut conn)?;

        Ok(count)
    }

    /// Get email verifications
    pub async fn get_email_verifications(&self) -> AuthResult<i64> {
        let mut conn = self
            .db_pool
            .get()
            .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

        let count = user_activity_logs
            .filter(activity_type.eq("email_verification"))
            .count()
            .get_result::<i64>(&mut conn)?;

        Ok(count)
    }

    /// Get user activity summary for admin dashboard
    pub async fn get_activity_summary(&self) -> AuthResult<ActivitySummary> {
        let mut conn = self
            .db_pool
            .get()
            .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

        let today = Utc::now().date_naive();
        let week_ago = Utc::now() - chrono::Duration::days(7);
        let month_ago = Utc::now() - chrono::Duration::days(30);

        let logins_today = user_activity_logs
            .filter(activity_type.eq("login"))
            .filter(created_at.gt(today.and_hms_opt(0, 0, 0).unwrap()))
            .count()
            .get_result::<i64>(&mut conn)?;

        let logins_week = user_activity_logs
            .filter(activity_type.eq("login"))
            .filter(created_at.gt(week_ago))
            .count()
            .get_result::<i64>(&mut conn)?;

        let logins_month = user_activity_logs
            .filter(activity_type.eq("login"))
            .filter(created_at.gt(month_ago))
            .count()
            .get_result::<i64>(&mut conn)?;

        let failed_logins = user_activity_logs
            .filter(activity_type.eq("failed_login"))
            .count()
            .get_result::<i64>(&mut conn)?;

        let password_resets = user_activity_logs
            .filter(activity_type.eq("password_reset_request"))
            .count()
            .get_result::<i64>(&mut conn)?;

        let email_verifications = user_activity_logs
            .filter(activity_type.eq("email_verification"))
            .count()
            .get_result::<i64>(&mut conn)?;

        Ok(ActivitySummary {
            logins_today,
            logins_week,
            logins_month,
            failed_logins,
            password_resets,
            email_verifications,
        })
    }

    /// Get audit logs with pagination and filters
    pub async fn get_audit_logs(
        &self,
        page: i64,
        per_page: i64,
        activity_type_filter: Option<&str>,
        user_id_filter: Option<Uuid>,
    ) -> AuthResult<Vec<UserActivityLog>> {
        let mut conn = self
            .db_pool
            .get()
            .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

        let offset = (page - 1) * per_page;
        let mut query = user_activity_logs.into_boxed();

        if let Some(act_type) = activity_type_filter {
            query = query.filter(activity_type.eq(act_type));
        }

        if let Some(uid) = user_id_filter {
            query = query.filter(user_id.eq(uid));
        }

        let logs = query
            .order(created_at.desc())
            .limit(per_page)
            .offset(offset)
            .load::<UserActivityLog>(&mut conn)?;

        Ok(logs)
    }

    /// Get total count of audit logs with filters
    pub async fn get_total_audit_logs(
        &self,
        activity_type_filter: Option<&str>,
        user_id_filter: Option<Uuid>,
    ) -> AuthResult<i64> {
        let mut conn = self
            .db_pool
            .get()
            .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

        let mut query = user_activity_logs.into_boxed();

        if let Some(act_type) = activity_type_filter {
            query = query.filter(activity_type.eq(act_type));
        }

        if let Some(uid) = user_id_filter {
            query = query.filter(user_id.eq(uid));
        }

        let count = query.count().get_result::<i64>(&mut conn)?;

        Ok(count)
    }

    /// Get user-specific audit logs
    pub async fn get_user_audit_logs(
        &self,
        target_user_id: Uuid,
        page: i64,
        per_page: i64,
    ) -> AuthResult<Vec<UserActivityLog>> {
        let mut conn = self
            .db_pool
            .get()
            .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

        let offset = (page - 1) * per_page;
        let logs = user_activity_logs
            .filter(user_id.eq(target_user_id))
            .order(created_at.desc())
            .limit(per_page)
            .offset(offset)
            .load::<UserActivityLog>(&mut conn)?;

        Ok(logs)
    }

    /// Get count of user-specific audit logs
    pub async fn get_user_audit_logs_count(&self, target_user_id: Uuid) -> AuthResult<i64> {
        let mut conn = self
            .db_pool
            .get()
            .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

        let count = user_activity_logs
            .filter(user_id.eq(target_user_id))
            .count()
            .get_result::<i64>(&mut conn)?;

        Ok(count)
    }
}

#[derive(Debug, serde::Serialize)]
pub struct ActivitySummary {
    pub logins_today: i64,
    pub logins_week: i64,
    pub logins_month: i64,
    pub failed_logins: i64,
    pub password_resets: i64,
    pub email_verifications: i64,
}

impl From<UserActivityLog> for ActivityLogResponse {
    fn from(activity: UserActivityLog) -> Self {
        Self {
            id: activity.id,
            user_id: activity.user_id,
            activity_type: activity.activity_type,
            description: activity.description,
            ip_address: activity.ip_address,
            user_agent: activity.user_agent,
            metadata: activity.metadata.map(|j| j.0),
            created_at: activity.created_at,
        }
    }
}
