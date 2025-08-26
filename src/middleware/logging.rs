use actix_web::{
    dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform},
    Error,
};
use futures_util::future::{ready, LocalBoxFuture, Ready};
use std::rc::Rc;
use std::time::Instant;
use tracing::{error, info, warn};

pub struct LoggingMiddleware;

impl LoggingMiddleware {
    pub fn new() -> Self {
        Self
    }
}

impl<S, B> Transform<S, ServiceRequest> for LoggingMiddleware
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type InitError = ();
    type Transform = LoggingMiddlewareService<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(LoggingMiddlewareService {
            service: Rc::new(service),
        }))
    }
}

pub struct LoggingMiddlewareService<S> {
    service: Rc<S>,
}

impl<S, B> Service<ServiceRequest> for LoggingMiddlewareService<S>
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
        let start_time = Instant::now();
        let method = req.method().clone();
        let uri = req.uri().clone();
        let client_ip = req
            .connection_info()
            .realip_remote_addr()
            .unwrap_or("0.0.0.0")
            .to_string();
        let user_agent = req
            .headers()
            .get("User-Agent")
            .and_then(|h| h.to_str().ok())
            .unwrap_or("Unknown")
            .to_string();

        Box::pin(async move {
            info!(
                "Request started: {} {} from {} (User-Agent: {})",
                method, uri, client_ip, user_agent
            );

            let res = svc.call(req).await;

            let duration = start_time.elapsed();
            let status = match &res {
                Ok(response) => response.status().as_u16(),
                Err(_) => 500,
            };

            match &res {
                Ok(_) => {
                    if status >= 400 {
                        warn!(
                            "Request completed: {} {} -> {} ({}ms)",
                            method,
                            uri,
                            status,
                            duration.as_millis()
                        );
                    } else {
                        info!(
                            "Request completed: {} {} -> {} ({}ms)",
                            method,
                            uri,
                            status,
                            duration.as_millis()
                        );
                    }
                }
                Err(e) => {
                    error!(
                        "Request failed: {} {} -> Error: {} ({}ms)",
                        method,
                        uri,
                        e,
                        duration.as_millis()
                    );
                }
            }

            res
        })
    }
}
