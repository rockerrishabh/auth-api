use actix_web::{
    dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform},
    error::ErrorUnauthorized,
    http::header,
    web, Error, HttpMessage, HttpRequest,
};
use futures_util::future::{ready, LocalBoxFuture, Ready};
use std::rc::Rc;
use uuid::Uuid;

use crate::config::AppConfig;
use crate::services::jwt::JwtService;

#[derive(Clone)]
pub struct AuthMiddleware {
    jwt_service: JwtService,
}

impl AuthMiddleware {
    pub fn new(config: AppConfig) -> Result<Self, Box<dyn std::error::Error>> {
        let jwt_service = JwtService::new(config.jwt).map_err(|e| {
            Box::new(std::io::Error::new(
                std::io::ErrorKind::Other,
                e.to_string(),
            ))
        })?;
        Ok(Self { jwt_service })
    }
}

impl<S, B> Transform<S, ServiceRequest> for AuthMiddleware
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type InitError = ();
    type Transform = AuthMiddlewareService<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(AuthMiddlewareService {
            service: Rc::new(service),
            jwt_service: self.jwt_service.clone(),
        }))
    }
}

pub struct AuthMiddlewareService<S> {
    service: Rc<S>,
    jwt_service: JwtService,
}

impl<S, B> Service<ServiceRequest> for AuthMiddlewareService<S>
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
        let jwt_service = self.jwt_service.clone();

        Box::pin(async move {
            // Extract token from Authorization header
            let token = req
                .headers()
                .get(header::AUTHORIZATION)
                .and_then(|auth_header| {
                    auth_header
                        .to_str()
                        .ok()
                        .and_then(|auth_str| auth_str.strip_prefix("Bearer "))
                });

            let token = match token {
                Some(token) => token,
                None => {
                    return Err(ErrorUnauthorized("Missing authorization token"));
                }
            };

            // Use JWT utility method to extract user_id from token
            let user_id = jwt_service
                .extract_user_id_from_token(token, "access")
                .map_err(|_| ErrorUnauthorized("Invalid token"))?;

            // Get claims for additional data (role, email)
            let claims = jwt_service
                .verify_access_token(token)
                .map_err(|_| ErrorUnauthorized("Invalid token"))?;

            req.extensions_mut().insert(user_id);
            req.extensions_mut().insert(claims);

            let res = svc.call(req).await?;
            Ok(res)
        })
    }
}

// Helper function to extract user_id from HttpRequest (for route handlers)
pub fn extract_user_id_from_request(req: &HttpRequest) -> Result<Uuid, Error> {
    // Extract token from Authorization header
    let token = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|auth_header| {
            auth_header
                .to_str()
                .ok()
                .and_then(|auth_str| auth_str.strip_prefix("Bearer "))
        });

    let token = match token {
        Some(token) => token,
        None => {
            return Err(ErrorUnauthorized("Missing authorization token"));
        }
    };

    // For route handlers, we need to create a temporary JwtService
    // In a production app, you'd want to store this in app data
    let config = req
        .app_data::<web::Data<crate::config::AppConfig>>()
        .ok_or_else(|| ErrorUnauthorized("Configuration not found"))?;

    let jwt_service = JwtService::new(config.jwt.clone())
        .map_err(|_| ErrorUnauthorized("Failed to initialize JWT service"))?;

    // Use JWT utility method to extract user_id from token
    let user_id = jwt_service
        .extract_user_id_from_token(token, "access")
        .map_err(|_| ErrorUnauthorized("Invalid user ID in token"))?;

    Ok(user_id)
}
