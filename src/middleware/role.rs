use actix_web::{
    dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform},
    error::ErrorForbidden,
    Error, HttpMessage,
};
use futures_util::future::{ready, LocalBoxFuture, Ready};
use std::rc::Rc;
use uuid::Uuid;

use crate::{db::DbPool, services::core::user::UserService};

pub struct RoleMiddleware {
    required_role: String,
    db_pool: DbPool,
}

impl RoleMiddleware {
    pub fn new(required_role: String, db_pool: DbPool) -> Self {
        Self {
            required_role,
            db_pool,
        }
    }
}

impl<S, B> Transform<S, ServiceRequest> for RoleMiddleware
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type InitError = ();
    type Transform = RoleMiddlewareService<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(RoleMiddlewareService {
            service: Rc::new(service),
            required_role: self.required_role.clone(),
            db_pool: self.db_pool.clone(),
        }))
    }
}

pub struct RoleMiddlewareService<S> {
    service: Rc<S>,
    required_role: String,
    db_pool: DbPool,
}

impl<S, B> Service<ServiceRequest> for RoleMiddlewareService<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let svc = self.service.clone();
        let required_role = self.required_role.clone();
        let db_pool = self.db_pool.clone();

        Box::pin(async move {
            // Extract user_id from request extensions (set by AuthMiddleware)
            let user_id = req
                .extensions()
                .get::<Uuid>()
                .copied()
                .ok_or_else(|| ErrorForbidden("User ID not found"))?;

            // Check if user has the required role
            let user_service = UserService::new(db_pool);
            let user = user_service
                .get_user_by_id(user_id)
                .await
                .map_err(|_| ErrorForbidden("Failed to get user"))?;

            let user = user.ok_or_else(|| ErrorForbidden("User not found"))?;

            if user.role.to_lowercase() != required_role.to_lowercase() {
                return Err(ErrorForbidden("Insufficient permissions"));
            }

            let res = svc.call(req).await?;
            Ok(res)
        })
    }
}
