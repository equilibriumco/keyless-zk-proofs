// Copyright (c) Aptos Foundation

use crate::external_resources::jwk_types::{
    FederatedJWKIssuer, FederatedJWKIssuerInterface, FederatedJWKs, JWKCache, JWKIssuer,
    JWKIssuerInterface, KeyID,
};
use crate::{metrics, utils};
use anyhow::{anyhow, Result};
use aptos_infallible::Mutex;
use aptos_keyless_common::input_processing::jwt::DecodedJWT;
use aptos_logger::{info, warn};
use aptos_time_service::{TimeService, TimeServiceTrait};
use aptos_types::jwks::rsa::RSA_JWK;
use serde_json::Value;
use std::collections::HashMap;
use std::time::Instant;
use std::{sync::Arc, time::Duration};
// TODO: merge this with the JWK fetcher used by the pepper service! The code is mostly duplicated.

// The frequency at which to log the JWK refresh status (per loop iteration)
const JWK_REFRESH_LOOP_LOG_FREQUENCY: u64 = 6; // e.g., 6 * 10s (per loop) = 60s per log

// Auth0 federated JWK constants
pub const AUTH0_ISSUER_NAME: &str = "auth0";
pub const AUTH0_REGEX_STR: &str = r"^https://[a-zA-Z0-9-]+\.us\.auth0\.com/$";
pub const AUTH0_JWK_URL_SUFFIX: &str = ".well-known/jwks.json";

// Cognito federated JWK constants
pub const COGNITO_ISSUER_NAME: &str = "cognito";
pub const COGNITO_REGEX_STR: &str =
    r"^https://cognito-idp\.[a-zA-Z0-9-_]+\.amazonaws\.com/[a-zA-Z0-9-_]+$";
pub const COGNITO_JWK_URL_SUFFIX: &str = "/.well-known/jwks.json";

/// Creates and initializes the federated JWKs map
fn initialize_federated_jwks() -> FederatedJWKs<FederatedJWKIssuer> {
    let mut federated_jwks = Vec::new();

    // Add the Auth0 federated JWKs
    let auth0_jwk = FederatedJWKIssuer::new(
        AUTH0_ISSUER_NAME.into(),
        AUTH0_JWK_URL_SUFFIX.into(),
        AUTH0_REGEX_STR.into(),
    );
    federated_jwks.push(auth0_jwk);

    // Add the cognito federated JWKs
    let cognito_jwk = FederatedJWKIssuer::new(
        COGNITO_ISSUER_NAME.into(),
        COGNITO_JWK_URL_SUFFIX.into(),
        COGNITO_REGEX_STR.into(),
    );
    federated_jwks.push(cognito_jwk);

    // Return the federated JWKs
    FederatedJWKs::new(federated_jwks)
}

/// Cap on the next-refresh interval derived from `Cache-Control: max-age=...`.
/// Even if Google advertises a multi-day TTL, never go longer than this.
const JWK_MAX_REFRESH_INTERVAL: Duration = Duration::from_secs(6 * 60 * 60);

/// Floor on the next-refresh interval. Avoids pathological-short `max-age`
/// values from causing a hammer-loop.
const JWK_MIN_REFRESH_INTERVAL: Duration = Duration::from_secs(60);

/// Parse `Cache-Control: max-age=N` from the response headers and return
/// the recommended next-refresh duration, clamped to
/// `[JWK_MIN_REFRESH_INTERVAL, JWK_MAX_REFRESH_INTERVAL]`.
///
/// Returns `None` when the response advertises `no-store`, `no-cache`,
/// `must-revalidate`, or has no usable `max-age`.
fn parse_cache_control_max_age(headers: &reqwest::header::HeaderMap) -> Option<Duration> {
    let value = headers.get(reqwest::header::CACHE_CONTROL)?.to_str().ok()?;

    // Honor "do not cache" directives — fall through to the configured
    // refresh rate.
    let lower = value.to_ascii_lowercase();
    if lower.contains("no-store") || lower.contains("no-cache") || lower.contains("must-revalidate")
    {
        return None;
    }

    // Find the `max-age=N` directive.
    for directive in value.split(',') {
        let directive = directive.trim();
        if let Some(rest) = directive.strip_prefix("max-age=") {
            if let Ok(secs) = rest.trim().parse::<u64>() {
                let raw = Duration::from_secs(secs);
                return Some(raw.clamp(JWK_MIN_REFRESH_INTERVAL, JWK_MAX_REFRESH_INTERVAL));
            }
        }
    }
    None
}

/// Fetches the JWKs from the given URL plus the recommended next-refresh
/// duration parsed from `Cache-Control: max-age=...` (when present).
pub async fn fetch_jwks_with_ttl(
    jwk_url: &str,
) -> Result<(HashMap<KeyID, Arc<RSA_JWK>>, Option<Duration>)> {
    // Create the request client
    let client = utils::create_request_client();

    // Fetch the JWKs from the URL
    let response = client
        .get(jwk_url)
        .send()
        .await
        .map_err(|error| anyhow!("Failed to fetch JWKs from {}! Error: {}", jwk_url, error))?;

    // Parse the Cache-Control TTL before consuming the response body.
    let ttl = parse_cache_control_max_age(response.headers());

    // Extract the response text
    let response_text = response.text().await.map_err(|error| {
        anyhow!(
            "Failed to extract response text from {}! Error: {}",
            jwk_url,
            error
        )
    })?;

    // Parse the JWKs from the response text
    let keys = parse_jwks(&response_text)?;

    Ok((keys, ttl))
}

/// Fetches the JWKs from the given URL.
///
/// Thin wrapper over [`fetch_jwks_with_ttl`] that discards the TTL —
/// preserves the existing public API while letting callers (notably the
/// background refresh loop) opt in to TTL-driven scheduling.
pub async fn fetch_jwks(jwk_url: &str) -> Result<HashMap<KeyID, Arc<RSA_JWK>>> {
    fetch_jwks_with_ttl(jwk_url).await.map(|(keys, _)| keys)
}

/// Returns a cached RSA JWK for the given issuer and key ID
pub fn get_cached_jwk_as_rsa(
    issuer: &String,
    key_id: &String,
    jwk_cache: JWKCache,
) -> Result<Arc<RSA_JWK>> {
    // Get the key set for the issuer
    let jwk_cache = jwk_cache.lock();
    let key_set = jwk_cache
        .get(issuer)
        .ok_or_else(|| anyhow!("Failed to get cached RSA JWK! Unknown issuer: {}", issuer))?;

    // Get the key for the given key ID
    let key = key_set
        .get(key_id)
        .ok_or_else(|| anyhow!("Failed to get cached RSA JWK! Unknown key ID: {}", key_id))?;

    Ok(key.clone())
}

/// Fetches the federated JWK for the given JWT
pub async fn get_federated_jwk<T: FederatedJWKIssuerInterface + Clone>(
    jwt: &DecodedJWT,
    federated_jwks: FederatedJWKs<T>,
) -> Result<Arc<RSA_JWK>> {
    // Identify the issuer from the JWT
    let jwt_issuer = &jwt.payload.iss;

    // Fetch the JWKs for the issuer
    let mut found_issuer = false;
    let mut jwks = HashMap::new();
    for federated_issuer in federated_jwks.get_issuers() {
        if federated_issuer.regex().is_match(jwt_issuer) {
            // Fetch the jwks from the URL
            let fetched_jwks = federated_issuer.fetch_jwks(jwt_issuer.into()).await?;

            // Update the keys and mark the issuer as found
            jwks = fetched_jwks;
            found_issuer = true;
            break;
        }
    }

    // Ensure the issuer was found
    if !found_issuer {
        return Err(anyhow!("Unsupported federated issuer: {}", jwt_issuer));
    }

    // Fetch the key for the given key ID
    let jwt_key_id = &jwt.header.kid;
    let key = jwks
        .get(jwt_key_id)
        .ok_or_else(|| anyhow!("Unknown kid: {}", jwt_key_id))?;
    Ok(key.clone())
}

/// Parses the JWKs from the given response text
fn parse_jwks(response_text: &str) -> Result<HashMap<KeyID, Arc<RSA_JWK>>> {
    // Parse the response text into a JSON value
    let response_json_value = serde_json::from_str::<Value>(response_text)
        .map_err(|error| anyhow!("Failed to parse response json! Error: {}", error))?;

    // Extract the "keys" array from the JSON value
    let keys: &Vec<Value> = response_json_value
        .get("keys")
        .ok_or_else(|| anyhow!("Failed to parse JWK json: \"keys\" entry not found!"))?
        .as_array()
        .ok_or_else(|| anyhow!("Failed to parse JWK json: \"keys\" entry not an array!"))?;

    // Parse each key, and filter out unsupported keys
    let key_map: HashMap<KeyID, Arc<RSA_JWK>> = keys
        .iter()
        .filter_map(|jwk_val| match RSA_JWK::try_from(jwk_val) {
            Ok(rsa_jwk) => {
                if rsa_jwk.e == "AQAB" {
                    Some((rsa_jwk.kid.clone(), Arc::new(rsa_jwk)))
                } else {
                    warn!("Unsupported RSA modulus for jwk: {}", jwk_val);
                    None
                }
            }
            Err(error) => {
                warn!("Error while parsing JWK: {}! {}", jwk_val, error);
                None
            }
        })
        .collect();

    Ok(key_map)
}

/// Starts the JWK refresh loops for the given issuers
pub fn start_jwk_fetchers(
    jwk_issuers: Vec<JWKIssuer>,
    jwk_refresh_rate: Duration,
) -> (JWKCache, FederatedJWKs<FederatedJWKIssuer>) {
    // Create the JWK cache
    let jwk_cache = Arc::new(Mutex::new(HashMap::new()));

    // Create and initialize the federated JWKs map
    let federated_jwks = initialize_federated_jwks();

    // Create the time service
    let time_service = TimeService::real();

    // Create the issuer map
    let jwk_issuer_map: HashMap<String, Arc<JWKIssuer>> = jwk_issuers
        .into_iter()
        .map(|issuer| (issuer.issuer_name(), Arc::new(issuer)))
        .collect();

    // Start the JWK refresh loops
    for (_, jwk_issuer) in jwk_issuer_map {
        start_jwk_refresh_loop(
            jwk_issuer,
            jwk_cache.clone(),
            jwk_refresh_rate,
            time_service.clone(),
        );
    }

    // Return the JWK cache
    (jwk_cache, federated_jwks)
}

/// Starts a background task that periodically fetches and caches the JWKs from the given issuer
pub fn start_jwk_refresh_loop(
    jwk_issuer: Arc<dyn JWKIssuerInterface + Send + Sync>,
    jwk_cache: JWKCache,
    jwk_refresh_rate: Duration,
    time_service: TimeService,
) {
    // Log the start of the task for the issuer
    let issuer_name = jwk_issuer.issuer_name();
    let issuer_jwk_url = jwk_issuer.issuer_jwk_url();
    info!(
        "Starting the JWK refresh loop for {}, URL: {}!",
        issuer_name, issuer_jwk_url
    );

    // Start the task
    tokio::spawn(async move {
        let mut loop_iteration_counter: u64 = 0;

        loop {
            // Fetch the JWKs from the URL
            let time_now = Instant::now();
            let fetch_result = jwk_issuer.fetch_jwks_with_ttl().await;
            let fetch_time = time_now.elapsed();
            let fetch_succeeded = fetch_result.is_ok();

            // Determine the next-refresh interval based on the response's
            // Cache-Control: max-age (when present), falling back to the
            // configured `jwk_refresh_rate` otherwise. On failure we keep
            // the previous cache entries (stale-serve) and retry at the
            // configured rate.
            let next_sleep = match &fetch_result {
                Ok((key_set, ttl)) => {
                    // Log the successful fetch
                    if loop_iteration_counter % JWK_REFRESH_LOOP_LOG_FREQUENCY == 0 {
                        info!(
                            "Successfully fetched the JWK in {:?}! Issuer: {}, URL: {}, Cache-Control TTL: {:?}, Key set: {:?}",
                            fetch_time,
                            issuer_jwk_url,
                            issuer_name,
                            ttl,
                            key_set
                        )
                    }

                    // Update the cache
                    jwk_cache
                        .lock()
                        .insert(issuer_name.clone(), key_set.clone());

                    // Honor the advertised TTL when present; otherwise
                    // fall back to the configured refresh rate.
                    ttl.unwrap_or(jwk_refresh_rate)
                }
                Err(error) => {
                    warn!(
                        "Failed to fetch the JWK in {:?}! Issuer: {}, URL: {}, Error: {} (serving previously-cached entries until next refresh)",
                        fetch_time, issuer_jwk_url, issuer_name, error
                    );
                    jwk_refresh_rate
                }
            };

            // Update the fetch metrics
            metrics::update_jwk_fetch_metrics(&issuer_name, fetch_succeeded, fetch_time);

            // Increment the loop iteration counter
            loop_iteration_counter = loop_iteration_counter.wrapping_add(1);

            // Sleep until the next refresh interval
            time_service.sleep(next_sleep).await;
        }
    });
}

#[cfg(test)]
mod cache_control_tests {
    use super::{parse_cache_control_max_age, JWK_MAX_REFRESH_INTERVAL, JWK_MIN_REFRESH_INTERVAL};
    use reqwest::header::{HeaderMap, HeaderValue, CACHE_CONTROL};
    use std::time::Duration;

    fn headers_with(value: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(CACHE_CONTROL, HeaderValue::from_str(value).unwrap());
        h
    }

    #[test]
    fn parses_typical_max_age() {
        let h = headers_with("public, max-age=3600, must-revalidate");
        // `must-revalidate` short-circuits caching even if max-age is present
        assert_eq!(parse_cache_control_max_age(&h), None);
    }

    #[test]
    fn parses_max_age_when_no_short_circuit_directives() {
        let h = headers_with("public, max-age=3600");
        assert_eq!(
            parse_cache_control_max_age(&h),
            Some(Duration::from_secs(3600))
        );
    }

    #[test]
    fn no_store_short_circuits() {
        let h = headers_with("no-store, max-age=3600");
        assert_eq!(parse_cache_control_max_age(&h), None);
    }

    #[test]
    fn missing_header_returns_none() {
        let h = HeaderMap::new();
        assert_eq!(parse_cache_control_max_age(&h), None);
    }

    #[test]
    fn caps_max_age_at_upper_bound() {
        let h = headers_with("max-age=2592000"); // 30 days
        assert_eq!(
            parse_cache_control_max_age(&h),
            Some(JWK_MAX_REFRESH_INTERVAL)
        );
    }

    #[test]
    fn floors_max_age_at_lower_bound() {
        let h = headers_with("max-age=5");
        assert_eq!(
            parse_cache_control_max_age(&h),
            Some(JWK_MIN_REFRESH_INTERVAL)
        );
    }

    #[test]
    fn unparseable_max_age_returns_none() {
        let h = headers_with("max-age=not-a-number");
        assert_eq!(parse_cache_control_max_age(&h), None);
    }
}
