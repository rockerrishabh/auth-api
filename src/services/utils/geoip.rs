use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeoLocation {
    pub ip: String,
    pub country: String,
    pub country_code: String,
    pub region: String,
    pub region_code: String,
    pub city: String,
    pub latitude: f64,
    pub longitude: f64,
    pub timezone: String,
    pub isp: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct IpApiResponse {
    #[serde(rename = "query")]
    pub ip: String,
    pub country: Option<String>,
    pub country_code: Option<String>,
    pub region: Option<String>,
    pub region_name: Option<String>,
    pub city: Option<String>,
    pub lat: Option<f64>,
    pub lon: Option<f64>,
    pub timezone: Option<String>,
    pub isp: Option<String>,
    pub status: String,
}

#[derive(Debug, Clone)]
pub struct GeoIPService {
    client: reqwest::Client,
    cache: Arc<RwLock<HashMap<String, GeoLocation>>>,
    cache_enabled: bool,
    api_endpoint: String,
}

impl GeoIPService {
    #[allow(dead_code)]
    pub fn new(cache_enabled: bool) -> Self {
        Self::new_with_timeout(cache_enabled, 5)
    }

    pub fn new_with_timeout(cache_enabled: bool, timeout_seconds: u64) -> Self {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(timeout_seconds))
            .user_agent("auth-api/1.0")
            .build()
            .expect("Failed to create HTTP client");

        Self {
            client,
            cache: Arc::new(RwLock::new(HashMap::new())),
            cache_enabled,
            api_endpoint: "http://ip-api.com/json".to_string(),
        }
    }

    pub fn with_endpoint(mut self, endpoint: String) -> Self {
        self.api_endpoint = endpoint;
        self
    }

    /// Lookup geolocation for an IP address
    pub async fn lookup(&self, ip: &str) -> Result<GeoLocation, GeoIPError> {
        // Skip lookup for localhost/private IPs
        if self.is_private_ip(ip) {
            return Ok(self.create_local_location(ip));
        }

        // Check cache first if enabled
        if self.cache_enabled {
            if let Some(cached) = self.get_cached_location(ip).await {
                return Ok(cached);
            }
        }

        // Perform API lookup
        let location = self.perform_api_lookup(ip).await?;

        // Cache the result if enabled
        if self.cache_enabled {
            self.cache_location(ip, &location).await;
        }

        Ok(location)
    }

    /// Get a formatted location string (City, Country)
    pub async fn get_location_string(&self, ip: &str) -> String {
        match self.lookup(ip).await {
            Ok(location) => {
                let mut parts = Vec::new();
                if !location.city.is_empty() && location.city != "Unknown" {
                    parts.push(location.city);
                }
                if !location.country.is_empty() && location.country != "Unknown" {
                    parts.push(location.country);
                }

                if parts.is_empty() {
                    "Unknown".to_string()
                } else {
                    parts.join(", ")
                }
            }
            Err(_) => "Unknown".to_string(),
        }
    }

    async fn perform_api_lookup(&self, ip: &str) -> Result<GeoLocation, GeoIPError> {
        let url = format!("{}/{}?fields=status,message,country,countryCode,region,regionName,city,lat,lon,timezone,isp,query", self.api_endpoint, ip);

        let response = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| GeoIPError::RequestError(e.to_string()))?;

        if !response.status().is_success() {
            return Err(GeoIPError::ApiError(format!("HTTP {}", response.status())));
        }

        let api_response: IpApiResponse = response
            .json()
            .await
            .map_err(|e| GeoIPError::ParseError(e.to_string()))?;

        if api_response.status != "success" {
            return Err(GeoIPError::ApiError("API request failed".to_string()));
        }

        Ok(GeoLocation {
            ip: api_response.ip,
            country: api_response
                .country
                .unwrap_or_else(|| "Unknown".to_string()),
            country_code: api_response
                .country_code
                .unwrap_or_else(|| "XX".to_string()),
            region: api_response
                .region_name
                .unwrap_or_else(|| "Unknown".to_string()),
            region_code: api_response.region.unwrap_or_else(|| "XX".to_string()),
            city: api_response.city.unwrap_or_else(|| "Unknown".to_string()),
            latitude: api_response.lat.unwrap_or(0.0),
            longitude: api_response.lon.unwrap_or(0.0),
            timezone: api_response.timezone.unwrap_or_else(|| "UTC".to_string()),
            isp: api_response.isp.unwrap_or_else(|| "Unknown".to_string()),
        })
    }

    fn is_private_ip(&self, ip: &str) -> bool {
        // Check for localhost and private IP ranges
        match ip {
            "127.0.0.1" | "::1" | "localhost" => true,
            _ => {
                if let Ok(ip_addr) = ip.parse::<std::net::IpAddr>() {
                    match ip_addr {
                        std::net::IpAddr::V4(ipv4) => {
                            ipv4.is_private() || ipv4.is_loopback() || ipv4.is_link_local()
                        }
                        std::net::IpAddr::V6(ipv6) => ipv6.is_loopback(),
                    }
                } else {
                    false
                }
            }
        }
    }

    fn create_local_location(&self, ip: &str) -> GeoLocation {
        GeoLocation {
            ip: ip.to_string(),
            country: "Local Network".to_string(),
            country_code: "LAN".to_string(),
            region: "Local".to_string(),
            region_code: "LOCAL".to_string(),
            city: "Localhost".to_string(),
            latitude: 0.0,
            longitude: 0.0,
            timezone: "UTC".to_string(),
            isp: "Local Network".to_string(),
        }
    }

    async fn get_cached_location(&self, ip: &str) -> Option<GeoLocation> {
        if !self.cache_enabled {
            return None;
        }

        let cache = self.cache.read().await;
        cache.get(ip).cloned()
    }

    async fn cache_location(&self, ip: &str, location: &GeoLocation) {
        if !self.cache_enabled {
            return;
        }

        let mut cache = self.cache.write().await;
        cache.insert(ip.to_string(), location.clone());

        // Keep cache size reasonable (max 1000 entries)
        if cache.len() > 1000 {
            // Remove oldest entries (simple FIFO by clearing half)
            let keys_to_remove: Vec<String> = cache.keys().take(cache.len() / 2).cloned().collect();
            for key in keys_to_remove {
                cache.remove(&key);
            }
        }
    }

    /// Clear the cache
    pub async fn clear_cache(&self) {
        if self.cache_enabled {
            let mut cache = self.cache.write().await;
            cache.clear();
        }
    }

    /// Get cache statistics
    pub async fn cache_stats(&self) -> (usize, bool) {
        if self.cache_enabled {
            let cache = self.cache.read().await;
            (cache.len(), true)
        } else {
            (0, false)
        }
    }
}

#[derive(Debug, Clone)]
pub enum GeoIPError {
    RequestError(String),
    ApiError(String),
    ParseError(String),
}

impl std::fmt::Display for GeoIPError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GeoIPError::RequestError(msg) => write!(f, "Request error: {}", msg),
            GeoIPError::ApiError(msg) => write!(f, "API error: {}", msg),
            GeoIPError::ParseError(msg) => write!(f, "Parse error: {}", msg),
        }
    }
}

impl std::error::Error for GeoIPError {}
