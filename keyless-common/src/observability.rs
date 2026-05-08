//! Shared tracing initializer and HTTP observability layers.

/// Which `fmt::Layer` flavor to install.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogFormat {
    Text,
    Json,
}

/// Parse the `LOG_FORMAT` env var. Unset or unrecognized → `Text`.
#[must_use]
pub fn log_format_from_env_var(raw: Option<&str>) -> LogFormat {
    match raw.map(str::trim).map(str::to_ascii_lowercase).as_deref() {
        Some("json") => LogFormat::Json,
        _ => LogFormat::Text,
    }
}

use std::env;
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

/// Install a global tracing subscriber based on `RUST_LOG` and `LOG_FORMAT`.
///
/// - Filter: `RUST_LOG` if set, else `info`.
/// - Format: text by default; `LOG_FORMAT=json` switches to JSON.
///
/// Safe to call more than once per process: uses `try_init` under the hood,
/// so repeated calls (e.g., from tests) silently no-op instead of panicking.
pub fn init() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let format = log_format_from_env_var(env::var("LOG_FORMAT").ok().as_deref());
    init_with(format, filter);
}

/// Install a global tracing subscriber with the given format + filter.
///
/// Split out from `init()` so tests can exercise the `LogFormat::*` matrix
/// deterministically without touching `RUST_LOG` / `LOG_FORMAT` env vars
/// (which would race across parallel tests).
pub fn init_with(format: LogFormat, filter: EnvFilter) {
    let registry = tracing_subscriber::registry().with(filter);
    let _ = match format {
        LogFormat::Json => registry.with(fmt::layer().json()).try_init(),
        LogFormat::Text => registry.with(fmt::layer()).try_init(),
    };
}

use axum::http::{HeaderValue, Request};
use tower_http::request_id::{MakeRequestId, RequestId};

/// A `MakeRequestId` that always mints a fresh `UUIDv4`, ignoring any inbound
/// `x-request-id` header.
///
/// The prover uses this because it's internet-facing: honouring caller-supplied
/// IDs lets an attacker inject arbitrary strings (newlines, log-injection
/// payloads, oversize blobs) straight into the observability pipeline. No
/// legitimate caller needs to pre-pick the ID.
#[derive(Clone, Default)]
pub struct AlwaysNewRequestId;

impl MakeRequestId for AlwaysNewRequestId {
    fn make_request_id<B>(&mut self, _request: &Request<B>) -> Option<RequestId> {
        let id = uuid::Uuid::new_v4().to_string();
        HeaderValue::from_str(&id).ok().map(RequestId::new)
    }
}

/// Fallback mapping from an HTTP status code to an `error_kind` label.
///
/// Used by `http_trace_layer`'s `on_response` to label extractor rejections
/// (Json parse, `DefaultBodyLimit`, missing content-type), unknown-route
/// hits, and wrong-method hits — anything that never reached a handler and
/// therefore never had a chance to record the field itself.
///
/// `400` and `422` both collapse to `bad_request` (axum 0.8 returns `400`
/// for JSON syntax errors and `422` for valid JSON that fails to deserialize
/// into the target type). `404` and `405` likewise — a client hitting a
/// non-existent path or a `POST`-only route with the wrong method is the
/// same taxonomy class of "client sent the wrong thing"; operators can still
/// discriminate via the `status` field on the completion line.
#[must_use]
pub fn map_status_to_error_kind(status: u16) -> Option<&'static str> {
    match status {
        400 | 404 | 405 | 422 => Some("bad_request"),
        413 => Some("body_too_large"),
        415 => Some("unsupported_media_type"),
        _ => None,
    }
}

use tower_http::request_id::{PropagateRequestIdLayer, SetRequestIdLayer};

/// Build the `SetRequestIdLayer` + `PropagateRequestIdLayer` pair used by
/// both services. `make` determines whether we honour an inbound
/// `x-request-id` or mint a fresh one:
/// - Prover: pass `AlwaysNewRequestId` — but use `always_fresh_request_id_layers`
///   instead; that function strips the inbound header before `SetRequestIdLayer`
///   can echo it back.
/// - Pepper-service: pass `tower_http::request_id::MakeRequestUuid` —
///   the prover is the only caller and its ID is trusted.
pub fn request_id_layers<M>(make: M) -> (SetRequestIdLayer<M>, PropagateRequestIdLayer)
where
    M: tower_http::request_id::MakeRequestId + Clone + Send + Sync + 'static,
{
    (
        SetRequestIdLayer::new(axum::http::HeaderName::from_static("x-request-id"), make),
        PropagateRequestIdLayer::x_request_id(),
    )
}

/// Build the three-layer stack the prover uses with `AlwaysNewRequestId`.
///
/// `tower_http::SetRequestIdLayer` only calls `make_request_id` when the
/// inbound request does **not** already carry `x-request-id`. That means a
/// caller can inject an arbitrary value that gets echoed straight back, which
/// is a log-injection vector. This function prepends a
/// [`StripInboundRequestIdLayer`] that removes the header before
/// `SetRequestIdLayer` runs, so `make_request_id` is always called and a
/// fresh UUID is always generated.
///
/// Layer application order (outermost → innermost):
/// ```text
/// propagate_id  ← echoes the extension → response header
/// http_trace    ← (inserted by the caller between set_id and propagate_id)
/// set_id        ← calls AlwaysNewRequestId::make_request_id
/// strip_id      ← removes any inbound x-request-id
/// ```
#[must_use]
pub fn always_fresh_request_id_layers() -> (
    StripInboundRequestIdLayer,
    SetRequestIdLayer<AlwaysNewRequestId>,
    PropagateRequestIdLayer,
) {
    let (set_id, propagate_id) = request_id_layers(AlwaysNewRequestId);
    (StripInboundRequestIdLayer, set_id, propagate_id)
}

/// Tower layer that removes the `x-request-id` header from every inbound
/// request. Must be applied **before** `SetRequestIdLayer` to prevent
/// caller-supplied IDs from being echoed.
#[derive(Clone, Copy, Debug, Default)]
pub struct StripInboundRequestIdLayer;

impl<S> tower::Layer<S> for StripInboundRequestIdLayer {
    type Service = StripInboundRequestId<S>;
    fn layer(&self, inner: S) -> Self::Service {
        StripInboundRequestId { inner }
    }
}

/// Tower service produced by [`StripInboundRequestIdLayer`].
#[derive(Clone, Debug)]
pub struct StripInboundRequestId<S> {
    inner: S,
}

impl<S, ReqBody> tower::Service<axum::http::Request<ReqBody>> for StripInboundRequestId<S>
where
    S: tower::Service<axum::http::Request<ReqBody>>,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = S::Future;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: axum::http::Request<ReqBody>) -> Self::Future {
        req.headers_mut().remove("x-request-id");
        self.inner.call(req)
    }
}

/// Marker inserted into a response's extensions when a user handler (rather
/// than an extractor / middleware) produced the response. The `http_trace_layer`
/// checks for it before applying its status→`error_kind` fallback: if the
/// handler ran, it's already recorded `error_kind` on the span (or left it
/// Empty for a 200), so overriding would drop information.
#[derive(Clone, Copy, Debug)]
pub struct HandlerRan;

/// Insert the `HandlerRan` marker into a response's extensions. Both the
/// prover's `prove` handler and the pepper-service's `pepper` handler call
/// this on their terminal `into_response` path.
pub fn mark_handler_ran(response: &mut axum::response::Response) {
    response.extensions_mut().insert(HandlerRan);
}

use std::time::Duration;

use axum::body::Body;
use tower_http::{
    classify::{ServerErrorsAsFailures, ServerErrorsFailureClass, SharedClassifier},
    trace::{
        DefaultOnBodyChunk, DefaultOnEos, DefaultOnRequest, MakeSpan, OnFailure, OnResponse,
        TraceLayer,
    },
};

/// `MakeSpan` impl for the shared `TraceLayer`.
///
/// Opens an `info_span!("http_request", …)` reading `request_id` from the
/// `x-request-id` request header. `SetRequestIdLayer` has already populated
/// that header by the time this runs (see layer order in Task 7).
#[derive(Clone, Copy, Debug, Default)]
pub struct MakeHttpSpan;

impl MakeSpan<Body> for MakeHttpSpan {
    fn make_span(&mut self, request: &axum::http::Request<Body>) -> tracing::Span {
        let request_id = request
            .headers()
            .get("x-request-id")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("-");
        tracing::info_span!(
            "http_request",
            request_id = %request_id,
            method = %request.method(),
            // `.path()` only — the full `uri()` includes the query string,
            // which is attacker-controlled and would let them choose log
            // content / volume on any rejected request.
            uri = %request.uri().path(),
            error_kind = tracing::field::Empty,
        )
    }
}

/// `OnResponse` impl that emits the single INFO "request complete" line and
/// applies the status→`error_kind` fallback when the handler didn't run.
#[derive(Clone, Copy, Debug, Default)]
pub struct OnHttpResponse;

impl OnResponse<Body> for OnHttpResponse {
    fn on_response(
        self,
        response: &axum::http::Response<Body>,
        latency: Duration,
        span: &tracing::Span,
    ) {
        let status = response.status().as_u16();
        #[allow(clippy::cast_possible_truncation)]
        let latency_ms = latency.as_millis() as u64;
        let handler_ran = response.extensions().get::<HandlerRan>().is_some();
        if !handler_ran {
            if let Some(kind) = map_status_to_error_kind(status) {
                span.record("error_kind", kind);
            }
        }
        let _enter = span.enter();
        tracing::info!(status, latency_ms, "request complete");
    }
}

/// No-op `OnFailure` impl.
///
/// `TraceLayer::new_for_http()` installs `DefaultOnFailure`, which emits an
/// ERROR event on any 5xx *after* our `OnHttpResponse` has already logged
/// the completion line. That duplicates signal and violates the spec's
/// "only the completion line emits at INFO/ERROR" invariant. We suppress it.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoOnFailure;

impl OnFailure<ServerErrorsFailureClass> for NoOnFailure {
    fn on_failure(
        &mut self,
        _failure_class: ServerErrorsFailureClass,
        _latency: Duration,
        _span: &tracing::Span,
    ) {
    }
}

/// Build the shared `TraceLayer` used by both services.
///
/// The seven `TraceLayer` generics are all explicit because we substitute
/// our own `MakeSpan`/`OnResponse`/`OnFailure` impls while leaving the
/// on-request / on-body-chunk / on-eos behaviours at their defaults.
#[must_use]
pub fn http_trace_layer() -> TraceLayer<
    SharedClassifier<ServerErrorsAsFailures>,
    MakeHttpSpan,
    DefaultOnRequest,
    OnHttpResponse,
    DefaultOnBodyChunk,
    DefaultOnEos,
    NoOnFailure,
> {
    TraceLayer::new_for_http()
        .make_span_with(MakeHttpSpan)
        .on_response(OnHttpResponse)
        .on_failure(NoOnFailure)
}

#[cfg(test)]
mod format_tests {
    use super::*;

    #[test]
    fn unset_is_text() {
        assert_eq!(log_format_from_env_var(None), LogFormat::Text);
    }

    #[test]
    fn empty_is_text() {
        assert_eq!(log_format_from_env_var(Some("")), LogFormat::Text);
    }

    #[test]
    fn json_is_json() {
        assert_eq!(log_format_from_env_var(Some("json")), LogFormat::Json);
    }

    #[test]
    fn mixed_case_json_is_json() {
        assert_eq!(log_format_from_env_var(Some(" JSON ")), LogFormat::Json);
    }

    #[test]
    fn text_is_text() {
        assert_eq!(log_format_from_env_var(Some("text")), LogFormat::Text);
    }

    #[test]
    fn unknown_is_text() {
        assert_eq!(log_format_from_env_var(Some("pretty")), LogFormat::Text);
    }

    #[test]
    fn init_with_text_does_not_panic() {
        super::init_with(
            super::LogFormat::Text,
            tracing_subscriber::EnvFilter::new("info"),
        );
    }

    #[test]
    fn init_with_json_does_not_panic() {
        super::init_with(
            super::LogFormat::Json,
            tracing_subscriber::EnvFilter::new("info"),
        );
    }

    #[test]
    fn init_default_does_not_panic() {
        // Exercises the unset-LOG_FORMAT path via the outer `init()` too.
        super::init();
        super::init();
    }

    #[test]
    fn map_400_is_bad_request() {
        assert_eq!(super::map_status_to_error_kind(400), Some("bad_request"));
    }

    #[test]
    fn map_422_is_bad_request() {
        // axum 0.8 returns 422 for valid JSON that fails to deserialize
        // (e.g. missing required fields); taxonomy-wise this is bad_request.
        assert_eq!(super::map_status_to_error_kind(422), Some("bad_request"));
    }

    #[test]
    fn map_404_is_bad_request() {
        assert_eq!(super::map_status_to_error_kind(404), Some("bad_request"));
    }

    #[test]
    fn map_405_is_bad_request() {
        assert_eq!(super::map_status_to_error_kind(405), Some("bad_request"));
    }

    #[test]
    fn map_413_is_body_too_large() {
        assert_eq!(super::map_status_to_error_kind(413), Some("body_too_large"));
    }

    #[test]
    fn map_415_is_unsupported_media_type() {
        assert_eq!(
            super::map_status_to_error_kind(415),
            Some("unsupported_media_type"),
        );
    }

    #[test]
    fn map_200_is_none() {
        assert_eq!(super::map_status_to_error_kind(200), None);
    }

    #[test]
    fn map_500_is_none() {
        assert_eq!(super::map_status_to_error_kind(500), None);
    }

    #[test]
    fn always_new_request_id_returns_fresh_each_call() {
        use axum::http::Request;
        use tower_http::request_id::MakeRequestId;

        let mut maker = super::AlwaysNewRequestId;
        let req1: Request<()> = Request::new(());
        let req2: Request<()> = Request::new(());
        let a = maker
            .make_request_id(&req1)
            .expect("some")
            .header_value()
            .clone();
        let b = maker
            .make_request_id(&req2)
            .expect("some")
            .header_value()
            .clone();
        assert_ne!(a, b, "each call must yield a fresh UUID");

        let a_str = a.to_str().unwrap();
        let parsed = uuid::Uuid::parse_str(a_str).expect("output must parse as UUID");
        assert_eq!(parsed.get_version(), Some(uuid::Version::Random));
    }

    #[test]
    fn always_new_request_id_ignores_inbound_header() {
        use axum::http::{HeaderValue, Request};
        use tower_http::request_id::MakeRequestId;

        let mut maker = super::AlwaysNewRequestId;
        let mut req: Request<()> = Request::new(());
        req.headers_mut().insert(
            "x-request-id",
            HeaderValue::from_static("caller-supplied-1234"),
        );
        let out = maker.make_request_id(&req).expect("some");
        let out_str = out.header_value().to_str().unwrap();
        assert_ne!(out_str, "caller-supplied-1234");
        let parsed = uuid::Uuid::parse_str(out_str).expect("output must parse as UUID");
        assert_eq!(parsed.get_version(), Some(uuid::Version::Random));
    }
}
