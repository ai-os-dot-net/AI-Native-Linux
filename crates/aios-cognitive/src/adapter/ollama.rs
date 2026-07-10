//! Ollama HTTP adapter for AI-OS.NET Rev.5 Live Cognition.
//!
//! Connects to a local Ollama server (`http://localhost:11434` by default)
//! via the Ollama REST API. Provides generate, streaming generate, model
//! listing, and health-check endpoints with typed errors and optional
//! cognitive evidence emission.

use std::sync::Arc;
use std::time::Instant;

use futures::stream::Stream;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::evidence_emit::CognitiveEvidenceEmitter;

/// Closed error taxonomy for Ollama HTTP adapter operations.
#[derive(Debug, Error)]
pub enum OllamaError {
    /// TCP connection to the Ollama server could not be established.
    #[error("connection to Ollama server failed: {0}")]
    ConnectionFailed(String),

    /// Request exceeded the configured timeout.
    #[error("request timed out")]
    Timeout,

    /// The requested model name is unknown to the Ollama server.
    #[error("model not found: {0}")]
    ModelNotFound(String),

    /// The server returned an HTTP status that does not match a known code.
    #[error("unexpected response from Ollama: {0}")]
    UnexpectedResponse(String),

    /// An error occurred while reading the streamed response body.
    #[error("streaming error: {0}")]
    StreamingError(String),

    /// JSON deserialization of the Ollama response body failed.
    #[error("JSON parse error: {0}")]
    ParseError(String),
}

/// Inference options forwarded to the Ollama server.
///
/// All fields are `Option` — `None` values are omitted from the serialised
/// JSON payload so the server applies its own defaults.
#[derive(Debug, Clone, Default, Serialize)]
pub struct OllamaOptions {
    /// Sampling temperature (0.0–2.0).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub temperature: Option<f32>,
    /// Nucleus sampling probability threshold.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub top_p: Option<f32>,
    /// Top-k sampling limit.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub top_k: Option<u32>,
    /// Maximum number of tokens to generate.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub num_predict: Option<u32>,
    /// Random seed for deterministic generation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub seed: Option<u32>,
    /// Size of the context window.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub num_ctx: Option<u32>,
}

/// Request body for `POST /api/generate`.
///
/// Serialises to the exact shape the Ollama REST API expects.
/// `stream` defaults to `false` in [`OllamaAdapter::generate`] and is
/// forced to `true` inside [`OllamaAdapter::generate_stream`].
#[derive(Debug, Clone, Serialize)]
pub struct OllamaGenerateRequest {
    /// Model name as known to the server (e.g. `"llama3:latest"`).
    pub model: String,
    /// The prompt text to send.
    pub prompt: String,
    /// When `Some(true)`, the server returns NDJSON partial responses.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stream: Option<bool>,
    /// Optional inference hyperparameters.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub options: Option<OllamaOptions>,
    /// System prompt (overrides the model's default system message).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub system: Option<String>,
    /// Custom prompt template (overrides the model's default template).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub template: Option<String>,
    /// Context vector from a previous response (for conversation continuation).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context: Option<Vec<i64>>,
}

impl OllamaGenerateRequest {
    /// Create a minimal generate request with a model name and prompt.
    #[must_use]
    pub fn new(model: impl Into<String>, prompt: impl Into<String>) -> Self {
        Self {
            model: model.into(),
            prompt: prompt.into(),
            stream: None,
            options: None,
            system: None,
            template: None,
            context: None,
        }
    }

    /// Attach inference options to the request.
    #[must_use]
    pub fn with_options(mut self, options: OllamaOptions) -> Self {
        self.options = Some(options);
        self
    }

    /// Set the system prompt for this request.
    #[must_use]
    pub fn with_system(mut self, system: impl Into<String>) -> Self {
        self.system = Some(system.into());
        self
    }
}

/// A single response object from `POST /api/generate`.
///
/// When `done` is `false` this represents a streaming fragment.
/// When `done` is `true` the final chunk carries token counts and timings.
#[derive(Debug, Clone, Deserialize)]
pub struct OllamaGenerateResponse {
    /// Model that produced this response.
    pub model: String,
    /// Generated text (partial for streaming fragments).
    pub response: String,
    /// `true` when this is the final chunk.
    #[serde(default)]
    pub done: bool,
    /// Opaque context vector (present in non-streaming responses and final chunks).
    #[serde(default)]
    pub context: Option<Vec<i64>>,
    /// Total wall-clock duration in nanoseconds (final chunk only).
    #[serde(default)]
    pub total_duration: Option<u64>,
    /// Model load duration in nanoseconds (final chunk only).
    #[serde(default)]
    pub load_duration: Option<u64>,
    /// Number of tokens in the prompt (final chunk only).
    #[serde(default)]
    pub prompt_eval_count: Option<u32>,
    /// Prompt evaluation duration in nanoseconds (final chunk only).
    #[serde(default)]
    pub prompt_eval_duration: Option<u64>,
    /// Number of generated tokens (final chunk only).
    #[serde(default)]
    pub eval_count: Option<u32>,
    /// Token generation duration in nanoseconds (final chunk only).
    #[serde(default)]
    pub eval_duration: Option<u64>,
}

/// A single model entry from the Ollama `/api/tags` response.
#[derive(Debug, Clone, Deserialize)]
pub struct OllamaModelInfo {
    /// Model name (e.g. `"llama3:latest"`).
    pub name: String,
    /// ISO-8601 timestamp of the last modification.
    #[serde(alias = "modified_at")]
    pub modified_at: String,
    /// On-disk size in bytes.
    pub size: u64,
}

/// Intermediate deserialisation target for `GET /api/tags`.
#[derive(Debug, Clone, Deserialize)]
struct OllamaTagsResponse {
    models: Vec<OllamaModelInfo>,
}

/// Typed HTTP client for a local Ollama server.
///
/// Wraps a [`reqwest::Client`] configured with a per-request timeout.
/// Optionally carries a [`CognitiveEvidenceEmitter`] that records
/// `MODEL_CALL` receipts on every `generate()` invocation.
#[derive(Clone)]
pub struct OllamaAdapter {
    base_url: String,
    client: reqwest::Client,
    timeout_seconds: u64,
    evidence_emitter: Option<Arc<CognitiveEvidenceEmitter>>,
}

impl std::fmt::Debug for OllamaAdapter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OllamaAdapter")
            .field("base_url", &self.base_url)
            .field("client", &"<reqwest::Client>")
            .field("timeout_seconds", &self.timeout_seconds)
            .field("evidence_emitter", &self.evidence_emitter.is_some())
            .finish()
    }
}

impl OllamaAdapter {
    /// Create an adapter targeting `base_url` (e.g. `"http://localhost:11434"`).
    ///
    /// The internal `reqwest::Client` is configured with a connect + read
    /// timeout of `timeout_seconds` seconds.
    #[must_use]
    pub fn new(base_url: &str, timeout_seconds: u64) -> Self {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(timeout_seconds))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());

        Self {
            base_url: base_url.to_string(),
            client,
            timeout_seconds,
            evidence_emitter: None,
        }
    }

    /// Attach a cognitive evidence emitter for automatic `MODEL_CALL`
    /// receipts on every `generate()` call.
    #[must_use]
    pub fn with_evidence_emitter(mut self, emitter: Arc<CognitiveEvidenceEmitter>) -> Self {
        self.evidence_emitter = Some(emitter);
        self
    }

    /// Send a non-streaming generate request to `POST /api/generate`.
    ///
    /// Forces `stream` to `false` regardless of what was set on the request.
    /// If an evidence emitter is attached, emits a `MODEL_CALL` receipt
    /// after a successful response.
    ///
    /// # Errors
    ///
    /// - [`OllamaError::ConnectionFailed`] — server unreachable.
    /// - [`OllamaError::Timeout`] — request exceeded the configured timeout.
    /// - [`OllamaError::ModelNotFound`] — HTTP 404 from the server.
    /// - [`OllamaError::ParseError`] — response body is not valid JSON.
    pub async fn generate(
        &self,
        request: OllamaGenerateRequest,
    ) -> Result<OllamaGenerateResponse, OllamaError> {
        let mut req = request;
        req.stream = Some(false);

        let start = Instant::now();

        let response = self
            .client
            .post(format!("{}/api/generate", self.base_url))
            .json(&req)
            .send()
            .await
            .map_err(|e| {
                if e.is_timeout() {
                    OllamaError::Timeout
                } else {
                    OllamaError::ConnectionFailed(e.to_string())
                }
            })?;

        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(match status.as_u16() {
                404 => OllamaError::ModelNotFound(body),
                _ => OllamaError::UnexpectedResponse(format!("HTTP {status}: {body}")),
            });
        }

        let parsed: OllamaGenerateResponse = response.json().await.map_err(|e| {
            if e.is_timeout() {
                OllamaError::Timeout
            } else {
                OllamaError::ParseError(e.to_string())
            }
        })?;

        let latency_ms = start.elapsed().as_millis() as u64;

        if let Some(ref emitter) = self.evidence_emitter {
            let tokens_in = parsed.prompt_eval_count.unwrap_or(0);
            let tokens_out = parsed.eval_count.unwrap_or(0);
            let _ = emitter
                .emit_model_call(&req.model, &req.model, tokens_in, tokens_out, 0, latency_ms)
                .await;
        }

        Ok(parsed)
    }

    /// Send a streaming generate request to `POST /api/generate`.
    ///
    /// Forces `stream` to `true`. Returns a [`Stream`] of partial
    /// [`OllamaGenerateResponse`] objects.  The final chunk has `done: true`
    /// and carries token counts and timings.
    ///
    /// The returned stream is `'static` and `Send` — it can be spawned on
    /// a tokio task. The full response body is buffered in memory before
    /// the first chunk is yielded.
    ///
    /// # Errors
    ///
    /// - [`OllamaError::ConnectionFailed`] — server unreachable.
    /// - [`OllamaError::Timeout`] — request exceeded the configured timeout.
    /// - [`OllamaError::ModelNotFound`] — HTTP 404 from the server.
    /// - [`OllamaError::StreamingError`] — failed to read the response body.
    pub async fn generate_stream(
        &self,
        request: OllamaGenerateRequest,
    ) -> Result<
        impl Stream<Item = Result<OllamaGenerateResponse, OllamaError>> + Send + 'static,
        OllamaError,
    > {
        let mut req = request;
        req.stream = Some(true);

        let response = self
            .client
            .post(format!("{}/api/generate", self.base_url))
            .json(&req)
            .send()
            .await
            .map_err(|e| {
                if e.is_timeout() {
                    OllamaError::Timeout
                } else {
                    OllamaError::ConnectionFailed(e.to_string())
                }
            })?;

        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(match status.as_u16() {
                404 => OllamaError::ModelNotFound(body),
                _ => OllamaError::UnexpectedResponse(format!("HTTP {status}: {body}")),
            });
        }

        let body = response
            .text()
            .await
            .map_err(|e| OllamaError::StreamingError(e.to_string()))?;

        let results: Vec<Result<OllamaGenerateResponse, OllamaError>> = body
            .lines()
            .filter(|line| !line.trim().is_empty())
            .map(|line| {
                serde_json::from_str::<OllamaGenerateResponse>(line)
                    .map_err(|e| OllamaError::ParseError(e.to_string()))
            })
            .collect();

        Ok(futures::stream::iter(results))
    }

    /// List all models known to the Ollama server via `GET /api/tags`.
    ///
    /// # Errors
    ///
    /// - [`OllamaError::ConnectionFailed`] — server unreachable.
    /// - [`OllamaError::Timeout`] — request exceeded the configured timeout.
    /// - [`OllamaError::UnexpectedResponse`] — non-success HTTP status.
    /// - [`OllamaError::ParseError`] — response body is not valid JSON.
    pub async fn list_models(&self) -> Result<Vec<OllamaModelInfo>, OllamaError> {
        let response = self
            .client
            .get(format!("{}/api/tags", self.base_url))
            .send()
            .await
            .map_err(|e| {
                if e.is_timeout() {
                    OllamaError::Timeout
                } else {
                    OllamaError::ConnectionFailed(e.to_string())
                }
            })?;

        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(OllamaError::UnexpectedResponse(format!(
                "HTTP {status}: {body}"
            )));
        }

        let parsed: OllamaTagsResponse = response.json().await.map_err(|e| {
            if e.is_timeout() {
                OllamaError::Timeout
            } else {
                OllamaError::ParseError(e.to_string())
            }
        })?;

        Ok(parsed.models)
    }

    /// Ping the Ollama server root (`GET /`) to check liveness.
    ///
    /// Returns `Ok(true)` when the server responds with a success status.
    /// Returns `Ok(false)` when the connection is refused or times out
    /// (server is down but no internal error occurred).
    ///
    /// # Errors
    ///
    /// Returns [`OllamaError::ConnectionFailed`] only for unexpected
    /// transport errors that are not connection-refused or timeout.
    pub async fn health_check(&self) -> Result<bool, OllamaError> {
        match self.client.get(&self.base_url).send().await {
            Ok(response) => Ok(response.status().is_success()),
            Err(e) => {
                if e.is_connect() || e.is_timeout() {
                    Ok(false)
                } else {
                    Err(OllamaError::ConnectionFailed(e.to_string()))
                }
            }
        }
    }

    /// Return the base URL this adapter targets.
    #[must_use]
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// Return the configured request timeout in seconds.
    #[must_use]
    pub fn timeout_seconds(&self) -> u64 {
        self.timeout_seconds
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::expect_used,
        clippy::panic,
        clippy::unwrap_used,
        clippy::unwrap_in_result,
        reason = "panic-on-failure is the idiomatic test signal"
    )]

    use super::*;
    use futures::StreamExt;

    fn test_adapter() -> OllamaAdapter {
        OllamaAdapter::new("http://localhost:11434", 30)
    }

    // -----------------------------------------------------------------------
    // Serialisation / deserialisation tests
    // -----------------------------------------------------------------------

    #[test]
    fn serialize_generate_request_defaults() {
        let req = OllamaGenerateRequest::new("llama3", "Why is the sky blue?");
        let json = serde_json::to_value(&req).unwrap();

        assert_eq!(json["model"], "llama3");
        assert_eq!(json["prompt"], "Why is the sky blue?");
        assert!(json.get("stream").is_none());
        assert!(json.get("options").is_none());
    }

    #[test]
    fn serialize_generate_request_with_stream_false() {
        let mut req = OllamaGenerateRequest::new("llama3", "hello");
        req.stream = Some(false);
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["stream"], false);
    }

    #[test]
    fn serialize_generate_request_with_options() {
        let options = OllamaOptions {
            temperature: Some(0.7),
            top_p: Some(0.9),
            top_k: None,
            num_predict: Some(256),
            seed: None,
            num_ctx: None,
        };
        let req = OllamaGenerateRequest::new("llama3", "hello").with_options(options);
        let json = serde_json::to_value(&req).unwrap();

        let opts = &json["options"];
        let temp = opts["temperature"].as_f64().expect("temperature is f64");
        assert!((temp - 0.7_f64).abs() < 0.001);
        let top_p_val = opts["top_p"].as_f64().expect("top_p is f64");
        assert!((top_p_val - 0.9_f64).abs() < 0.001);
        assert_eq!(opts["num_predict"], 256);
        assert!(opts.get("top_k").is_none());
        assert!(opts.get("seed").is_none());
    }

    #[test]
    fn serialize_generate_request_with_system() {
        let req = OllamaGenerateRequest::new("llama3", "hello").with_system("You are helpful.");
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["system"], "You are helpful.");
    }

    #[test]
    fn deserialize_complete_generate_response() {
        let raw = r#"{
            "model": "llama3",
            "created_at": "2023-08-04T19:22:45.499127Z",
            "response": "The sky is blue because of Rayleigh scattering.",
            "done": true,
            "context": [1, 2, 3],
            "total_duration": 5043500667,
            "load_duration": 5025959,
            "prompt_eval_count": 26,
            "prompt_eval_duration": 325953000,
            "eval_count": 290,
            "eval_duration": 4709213000
        }"#;

        let parsed: OllamaGenerateResponse =
            serde_json::from_str(raw).expect("deserialize complete response");

        assert_eq!(parsed.model, "llama3");
        assert!(
            parsed.response.contains("Rayleigh scattering"),
            "response text present"
        );
        assert!(parsed.done);
        assert_eq!(parsed.context, Some(vec![1, 2, 3]));
        assert_eq!(parsed.total_duration, Some(5_043_500_667));
        assert_eq!(parsed.prompt_eval_count, Some(26));
        assert_eq!(parsed.eval_count, Some(290));
        assert_eq!(parsed.eval_duration, Some(4_709_213_000));
    }

    #[test]
    fn deserialize_partial_stream_response() {
        let raw = r#"{"model":"llama3","created_at":"2023-08-04T19:22:45.499127Z","response":"The","done":false}"#;

        let parsed: OllamaGenerateResponse =
            serde_json::from_str(raw).expect("deserialize partial response");

        assert_eq!(parsed.model, "llama3");
        assert_eq!(parsed.response, "The");
        assert!(!parsed.done);
        assert!(parsed.context.is_none());
        assert!(parsed.prompt_eval_count.is_none());
    }

    #[test]
    fn deserialize_final_stream_chunk_with_total_duration() {
        let raw = r#"{"model":"llama3","created_at":"2023-08-04T19:22:45.499127Z","response":"","done":true,"total_duration":5043500667,"load_duration":5025959,"prompt_eval_count":26,"eval_count":290}"#;

        let parsed: OllamaGenerateResponse =
            serde_json::from_str(raw).expect("deserialize final chunk");

        assert!(parsed.done);
        assert!(parsed.response.is_empty());
        assert_eq!(parsed.total_duration, Some(5_043_500_667));
        assert_eq!(parsed.eval_count, Some(290));
    }

    #[test]
    fn deserialize_tags_response() {
        let raw = r#"{
            "models": [
                {
                    "name": "llama3:latest",
                    "model": "llama3:latest",
                    "modified_at": "2023-08-04T19:22:45.499127Z",
                    "size": 4936700928,
                    "digest": "abc123",
                    "details": {
                        "format": "gguf",
                        "family": "llama",
                        "parameter_size": "8B"
                    }
                },
                {
                    "name": "mistral:7b",
                    "modified_at": "2024-01-15T10:30:00Z",
                    "size": 4370000000
                }
            ]
        }"#;

        let parsed: OllamaTagsResponse = serde_json::from_str(raw).expect("deserialize tags");

        assert_eq!(parsed.models.len(), 2);
        assert_eq!(parsed.models[0].name, "llama3:latest");
        assert_eq!(parsed.models[0].size, 4_936_700_928);
        assert_eq!(parsed.models[1].name, "mistral:7b");
        assert_eq!(parsed.models[1].size, 4_370_000_000);
    }

    #[test]
    fn deserialize_model_info_minimal() {
        let raw =
            r#"{"name":"codellama:7b","modified_at":"2024-06-01T00:00:00Z","size":4000000000}"#;

        let info: OllamaModelInfo = serde_json::from_str(raw).expect("deserialize model info");

        assert_eq!(info.name, "codellama:7b");
        assert_eq!(info.size, 4_000_000_000);
    }

    // -----------------------------------------------------------------------
    // OllamaError tests
    // -----------------------------------------------------------------------

    #[test]
    fn error_displays_meaningful_message() {
        let err = OllamaError::ConnectionFailed("refused".into());
        assert!(err.to_string().contains("refused"));

        let err = OllamaError::ModelNotFound("unknown model".into());
        assert!(err.to_string().contains("unknown model"));

        let err = OllamaError::Timeout;
        assert!(err.to_string().contains("timed out"));
    }

    // -----------------------------------------------------------------------
    // Adapter construction tests
    // -----------------------------------------------------------------------

    #[test]
    fn adapter_constructs_with_custom_timeout() {
        let adapter = OllamaAdapter::new("http://localhost:11434", 60);
        assert_eq!(adapter.base_url(), "http://localhost:11434");
        assert_eq!(adapter.timeout_seconds(), 60);
    }

    #[test]
    fn adapter_debug_does_not_leak_client() {
        let adapter = test_adapter();
        let debug_str = format!("{adapter:?}");
        assert!(debug_str.contains("OllamaAdapter"));
        assert!(debug_str.contains("<reqwest::Client>"), "client is opaque");
    }

    // -----------------------------------------------------------------------
    // Connection error test (no server running)
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn generate_connection_refused_returns_error() {
        let adapter = OllamaAdapter::new("http://127.0.0.1:19999", 1);

        let req = OllamaGenerateRequest::new("llama3", "hello");
        let result = adapter.generate(req).await;

        assert!(result.is_err(), "should fail with no server");
        match result {
            Err(OllamaError::ConnectionFailed(_) | OllamaError::Timeout) => {}
            other => panic!("expected ConnectionFailed or Timeout, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn health_check_returns_false_when_no_server() {
        let adapter = OllamaAdapter::new("http://127.0.0.1:19999", 1);
        let healthy = adapter.health_check().await;
        assert!(
            matches!(healthy, Ok(false)),
            "expected Ok(false) with no server, got {healthy:?}"
        );
    }

    // -----------------------------------------------------------------------
    // Streaming unit test (parse multiple NDJSON lines)
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn parse_stream_lines_yields_correct_token_accumulation() {
        let lines: Vec<Result<OllamaGenerateResponse, OllamaError>> =
            futures::stream::iter([
                r#"{"model":"llama3","response":"The","done":false}"#,
                r#"{"model":"llama3","response":" sky","done":false}"#,
                r#"{"model":"llama3","response":" is","done":false}"#,
                r#"{"model":"llama3","response":" blue","done":false}"#,
                r#"{"model":"llama3","response":"","done":true,"total_duration":5000000000,"prompt_eval_count":5,"eval_count":4}"#,
            ])
            .filter_map(|raw| async {
                match serde_json::from_str::<OllamaGenerateResponse>(raw) {
                    Ok(resp) => Some(Ok(resp)),
                    Err(e) => Some(Err(OllamaError::ParseError(e.to_string()))),
                }
            })
            .collect()
            .await;

        let results: Vec<OllamaGenerateResponse> =
            lines.into_iter().map(|r| r.expect("parse ok")).collect();

        assert_eq!(results.len(), 5);
        assert!(!results[0].done);
        assert!(!results[1].done);
        assert!(results[4].done);
        assert_eq!(results[4].eval_count, Some(4));
        assert_eq!(results[4].prompt_eval_count, Some(5));

        let full_text: String = results.iter().map(|r| r.response.as_str()).collect();
        assert_eq!(full_text, "The sky is blue");
    }

    // -----------------------------------------------------------------------
    // OllamaOptions default
    // -----------------------------------------------------------------------

    #[test]
    fn options_default_has_all_none() {
        let opts = OllamaOptions::default();
        assert!(opts.temperature.is_none());
        assert!(opts.top_p.is_none());
        assert!(opts.top_k.is_none());
        assert!(opts.num_predict.is_none());
        assert!(opts.seed.is_none());
        assert!(opts.num_ctx.is_none());
    }

    // -----------------------------------------------------------------------
    // OllamaGenerateRequest::with_options chain
    // -----------------------------------------------------------------------

    #[test]
    fn request_builder_chain() {
        let req = OllamaGenerateRequest::new("mistral", "hi")
            .with_options(OllamaOptions {
                temperature: Some(0.5),
                top_p: None,
                top_k: None,
                num_predict: None,
                seed: None,
                num_ctx: None,
            })
            .with_system("Be concise.");

        assert_eq!(req.model, "mistral");
        assert_eq!(req.prompt, "hi");
        assert_eq!(req.options.as_ref().and_then(|o| o.temperature), Some(0.5));
        assert_eq!(req.system.as_deref(), Some("Be concise."));
    }
}
