use actix_web::{
    dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform},
    error::ErrorTooManyRequests,
    Error,
};
use futures_util::future::{ready, LocalBoxFuture, Ready};
use std::collections::HashMap;
use std::rc::Rc;
use std::sync::Mutex;
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
struct RateLimitEntry {
    count: u32,
    reset_time: Instant,
}

pub struct RateLimitMiddleware {
    max_requests: u32,
    window_duration: Duration,
    storage: Rc<Mutex<HashMap<String, RateLimitEntry>>>,
}

impl RateLimitMiddleware {
    pub fn new(max_requests: u32, window_duration: Duration) -> Self {
        Self {
            max_requests,
            window_duration,
            storage: Rc::new(Mutex::new(HashMap::new())),
        }
    }
}

impl<S, B> Transform<S, ServiceRequest> for RateLimitMiddleware
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type InitError = ();
    type Transform = RateLimitMiddlewareService<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(RateLimitMiddlewareService {
            service: Rc::new(service),
            max_requests: self.max_requests,
            window_duration: self.window_duration,
            storage: self.storage.clone(),
        }))
    }
}

pub struct RateLimitMiddlewareService<S> {
    service: Rc<S>,
    max_requests: u32,
    window_duration: Duration,
    storage: Rc<Mutex<HashMap<String, RateLimitEntry>>>,
}

impl<S, B> Service<ServiceRequest> for RateLimitMiddlewareService<S>
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
        let max_requests = self.max_requests;
        let window_duration = self.window_duration;
        let storage = self.storage.clone();

        Box::pin(async move {
            let client_ip = req
                .connection_info()
                .realip_remote_addr()
                .unwrap_or("0.0.0.0")
                .to_string();

            let now = Instant::now();
            let mut storage = storage.lock().unwrap();

            // Clean up expired entries
            storage.retain(|_, entry| now.duration_since(entry.reset_time) < window_duration);

            let entry = storage
                .entry(client_ip.clone())
                .or_insert_with(|| RateLimitEntry {
                    count: 0,
                    reset_time: now + window_duration,
                });

            if entry.count >= max_requests {
                return Err(ErrorTooManyRequests("Rate limit exceeded"));
            }

            entry.count += 1;

            let res = svc.call(req).await?;
            Ok(res)
        })
    }
}
