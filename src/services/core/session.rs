use chrono::{DateTime, Duration, Utc};
use diesel::{ExpressionMethods, OptionalExtension, QueryDsl, RunQueryDsl};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    db::{models::UserSession, DbPool},
    error::{AuthError, AuthResult},
};

// Import schema for database operations
use crate::db::schemas::user_sessions::dsl::*;

#[derive(Debug, Serialize, Deserialize)]
pub struct SessionRequest {
    pub user_id: Uuid,
    pub ip_address: String,
    pub user_agent: String,
    pub device_info: Option<serde_json::Value>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SessionResponse {
    pub id: Uuid,
    pub user_id: Uuid,
    pub session_token: String,
    pub expires_at: DateTime<Utc>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub device_info: Option<serde_json::Value>,
    pub is_active: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Clone)]
pub struct SessionService {
    db_pool: DbPool,
}

impl SessionService {
    pub fn new(db_pool: DbPool) -> Self {
        Self { db_pool }
    }

    pub async fn create_session(&self, request: SessionRequest) -> AuthResult<SessionResponse> {
        let mut conn = self
            .db_pool
            .get()
            .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

        // Check if user already has an active session with the same IP and user agent
        let existing_session = user_sessions
            .filter(user_id.eq(request.user_id))
            .filter(is_active.eq(true))
            .filter(ip_address.eq(&request.ip_address))
            .filter(user_agent.eq(&request.user_agent))
            .first::<UserSession>(&mut conn)
            .optional()?;

        if let Some(existing) = existing_session {
            // Update the existing session's last activity and extend expiry
            let updated_session = diesel::update(user_sessions.filter(id.eq(existing.id)))
                .set((
                    last_activity.eq(Some(Utc::now())),
                    expires_at.eq(Utc::now() + Duration::hours(24)),
                    updated_at.eq(Utc::now()),
                ))
                .get_result::<UserSession>(&mut conn)?;

            return Ok(SessionResponse {
                id: updated_session.id,
                user_id: updated_session.user_id,
                session_token: updated_session.session_token,
                expires_at: updated_session.expires_at,
                ip_address: updated_session.ip_address,
                user_agent: updated_session.user_agent,
                device_info: updated_session.device_info.map(|j| j.0),
                is_active: updated_session.is_active,
                created_at: updated_session.created_at,
                updated_at: updated_session.updated_at,
            });
        }

        // Create new session if no matching session exists
        let new_session = crate::db::models::NewUserSession {
            user_id: request.user_id,
            session_token: uuid::Uuid::new_v4().to_string(),
            expires_at: Utc::now() + Duration::hours(24),
            ip_address: Some(request.ip_address),
            user_agent: Some(request.user_agent),
            device_info: request.device_info.map(|v| diesel_json::Json(v)),
        };

        let inserted_session = diesel::insert_into(user_sessions)
            .values(&new_session)
            .get_result::<UserSession>(&mut conn)?;

        Ok(SessionResponse {
            id: inserted_session.id,
            user_id: inserted_session.user_id,
            session_token: inserted_session.session_token,
            expires_at: inserted_session.expires_at,
            ip_address: inserted_session.ip_address,
            user_agent: inserted_session.user_agent,
            device_info: inserted_session.device_info.map(|j| j.0),
            is_active: inserted_session.is_active,
            created_at: inserted_session.created_at,
            updated_at: inserted_session.updated_at,
        })
    }

    /// Get session by token
    pub async fn get_session(&self, token: &str) -> AuthResult<Option<SessionResponse>> {
        let mut conn = self
            .db_pool
            .get()
            .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

        let session = user_sessions
            .filter(session_token.eq(token))
            .filter(is_active.eq(true))
            .first::<UserSession>(&mut conn)
            .optional()?;

        Ok(session.map(|s| SessionResponse {
            id: s.id,
            user_id: s.user_id,
            session_token: s.session_token,
            expires_at: s.expires_at,
            ip_address: s.ip_address,
            user_agent: s.user_agent,
            device_info: s.device_info.map(|j| j.0),
            is_active: s.is_active,
            created_at: s.created_at,
            updated_at: s.updated_at,
        }))
    }

    /// Revoke all user sessions
    pub async fn revoke_all_user_sessions(&self, target_user_id: Uuid) -> AuthResult<u64> {
        let mut conn = self
            .db_pool
            .get()
            .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

        let updated_count = diesel::update(user_sessions.filter(user_id.eq(target_user_id)))
            .set((is_active.eq(false), updated_at.eq(Utc::now())))
            .execute(&mut conn)?;

        Ok(updated_count as u64)
    }

    /// Get user's active sessions with pagination
    pub async fn get_user_sessions(
        &self,
        target_user_id: Uuid,
        page: i64,
        per_page: i64,
    ) -> AuthResult<Vec<UserSession>> {
        let mut conn = self
            .db_pool
            .get()
            .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

        let offset = (page - 1) * per_page;
        let sessions = user_sessions
            .filter(user_id.eq(target_user_id))
            .filter(is_active.eq(true))
            .order(created_at.desc())
            .limit(per_page)
            .offset(offset)
            .load::<UserSession>(&mut conn)?;

        Ok(sessions)
    }

    /// Get count of user's active sessions
    pub async fn get_user_sessions_count(&self, target_user_id: Uuid) -> AuthResult<i64> {
        let mut conn = self
            .db_pool
            .get()
            .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

        let count = user_sessions
            .filter(user_id.eq(target_user_id))
            .filter(is_active.eq(true))
            .count()
            .get_result::<i64>(&mut conn)?;

        Ok(count)
    }

    /// Revoke a specific user session
    pub async fn revoke_user_session(
        &self,
        target_user_id: Uuid,
        session_id: Uuid,
    ) -> AuthResult<bool> {
        let mut conn = self
            .db_pool
            .get()
            .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

        // Check if session belongs to user and is active
        let session = user_sessions
            .filter(id.eq(session_id))
            .filter(user_id.eq(target_user_id))
            .filter(is_active.eq(true))
            .first::<UserSession>(&mut conn)
            .optional()?;

        if let Some(_session) = session {
            // Revoke the session
            diesel::update(user_sessions)
                .filter(id.eq(session_id))
                .set(is_active.eq(false))
                .execute(&mut conn)?;

            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Revoke all other user sessions (keep the current one)
    pub async fn revoke_other_user_sessions(
        &self,
        target_user_id: Uuid,
        current_token: &str,
    ) -> AuthResult<i64> {
        let mut conn = self
            .db_pool
            .get()
            .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

        // Revoke all other active sessions for the user
        let result = diesel::update(
            user_sessions
                .filter(user_id.eq(target_user_id))
                .filter(is_active.eq(true))
                .filter(crate::db::schemas::user_sessions::dsl::session_token.ne(current_token)),
        )
        .set(is_active.eq(false))
        .execute(&mut conn)?;

        Ok(result as i64)
    }

    /// Get total sessions count
    pub async fn get_total_sessions_count(&self) -> AuthResult<i64> {
        let mut conn = self
            .db_pool
            .get()
            .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

        let count = user_sessions.count().get_result::<i64>(&mut conn)?;
        Ok(count)
    }

    /// Get active sessions count
    pub async fn get_active_sessions_count(&self) -> AuthResult<i64> {
        let mut conn = self
            .db_pool
            .get()
            .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

        let count = user_sessions
            .filter(is_active.eq(true))
            .count()
            .get_result::<i64>(&mut conn)?;

        Ok(count)
    }

    /// Get or create session for user (prevents duplicate sessions)
    pub async fn get_or_create_session(
        &self,
        request: SessionRequest,
    ) -> AuthResult<SessionResponse> {
        // First try to find an existing active session
        let existing_sessions = self.get_user_sessions(request.user_id, 1, 10).await?;

        // Check if there's a session with the same IP and user agent
        for session in existing_sessions {
            if session.ip_address.as_deref() == Some(&request.ip_address)
                && session.user_agent.as_deref() == Some(&request.user_agent)
            {
                // Update the existing session
                return self.update_session_activity(session.id).await;
            }
        }

        // If no matching session found, create a new one
        self.create_session(request).await
    }

    /// Update session activity (extends expiry and updates last_activity)
    pub async fn update_session_activity(&self, session_id: Uuid) -> AuthResult<SessionResponse> {
        let mut conn = self
            .db_pool
            .get()
            .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

        let updated_session = diesel::update(user_sessions.filter(id.eq(session_id)))
            .set((
                last_activity.eq(Some(Utc::now())),
                expires_at.eq(Utc::now() + Duration::hours(24)),
                updated_at.eq(Utc::now()),
            ))
            .get_result::<UserSession>(&mut conn)?;

        Ok(SessionResponse {
            id: updated_session.id,
            user_id: updated_session.user_id,
            session_token: updated_session.session_token,
            expires_at: updated_session.expires_at,
            ip_address: updated_session.ip_address,
            user_agent: updated_session.user_agent,
            device_info: updated_session.device_info.map(|j| j.0),
            is_active: updated_session.is_active,
            created_at: updated_session.created_at,
            updated_at: updated_session.updated_at,
        })
    }
}
