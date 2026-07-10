//! vLLM OpenAI-compatible HTTP adapter for AI-OS.NET Rev.5 Live Cognition.
//!
//! Connects to a vLLM server via its OpenAI-compatible REST API endpoints:
//! `POST /v1/completions`, `POST /v1/chat/completions`, `GET /v1/models`,
//! and `GET /health`. Provides completion, chat, streaming, model listing,
//! and health-check endpoints with typed errors and optional cognitive
//! evidence emission.

use std::sync::Arc;
use std::time::Instant;

use futures::stream::Stream;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::evidence_emit::CognitiveEvidenceEmitter;

/// Closed error taxonomy for vLLM HTTP adapter operations.
#[derive(Debug, Error)]
pub enum VllmError {
    /// TCP connection to the vLLM server could not be established.
    #[error("connection to vLLM server failed: {0}")]
    ConnectionFailed(String),

    /// Request exceeded the configured timeout.
    #[error("request timed out")]
    Timeout,

    /// The requested model name is unknown to the vLLM server.
    #[error("model not found: {0}")]
    ModelNotFound(String),

    /// The server returned an HTTP status that does not match a known code.
    #[error("unexpected response from vLLM: {0}")]
    UnexpectedResponse(String),

    /// An error occurred while reading the streamed response body.
    #[error("streaming error: {0}")]
    StreamingError(String),

    /// JSON deserialization of the vLLM response body failed.
    #[error("JSON parse error: {0}")]
    ParseError(String),
}

// ---------------------------------------------------------------------------
// Completion types
// ---------------------------------------------------------------------------

/// Token usage statistics returned in non-streaming responses.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct VllmUsage {
    /// Number of tokens in the prompt.
    pub prompt_tokens: u32,
    /// Number of generated tokens.
    pub completion_tokens: u32,
    /// Total tokens (prompt + completion).
    pub total_tokens: u32,
}

/// A single choice in a completion response.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct VllmChoice {
    /// Generated text for this choice.
    pub text: String,
    /// Index of this choice in the list.
    pub index: u32,
    /// Reason generation stopped (`"stop"`, `"length"`, etc.) — `None` in streaming chunks.
    #[serde(default)]
    pub finish_reason: Option<String>,
}

/// Request body for `POST /v1/completions`.
///
/// All optional fields use `skip_serializing_if` so the server applies its
/// own defaults when they are omitted.
#[derive(Debug, Clone, Serialize)]
pub struct VllmCompletionRequest {
    /// Model name as known to the vLLM server.
    pub model: String,
    /// The prompt text to complete.
    pub prompt: String,
    /// Maximum number of tokens to generate.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_tokens: Option<u32>,
    /// Sampling temperature (0.0–2.0).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub temperature: Option<f32>,
    /// Nucleus sampling probability threshold.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub top_p: Option<f32>,
    /// Stream partial progress as SSE events.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stream: Option<bool>,
    /// Stop sequences — generation halts when any is produced.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stop: Option<Vec<String>>,
}

impl VllmCompletionRequest {
    /// Create a minimal completion request with a model name and prompt.
    #[must_use]
    pub fn new(model: impl Into<String>, prompt: impl Into<String>) -> Self {
        Self {
            model: model.into(),
            prompt: prompt.into(),
            max_tokens: None,
            temperature: None,
            top_p: None,
            stream: None,
            stop: None,
        }
    }

    /// Set the maximum number of tokens to generate.
    #[must_use]
    pub fn with_max_tokens(mut self, max_tokens: u32) -> Self {
        self.max_tokens = Some(max_tokens);
        self
    }

    /// Set the sampling temperature.
    #[must_use]
    pub fn with_temperature(mut self, temperature: f32) -> Self {
        self.temperature = Some(temperature);
        self
    }

    /// Set nucleus sampling probability.
    #[must_use]
    pub fn with_top_p(mut self, top_p: f32) -> Self {
        self.top_p = Some(top_p);
        self
    }

    /// Set stop sequences.
    #[must_use]
    pub fn with_stop(mut self, stop: Vec<String>) -> Self {
        self.stop = Some(stop);
        self
    }
}

/// Response body from `POST /v1/completions`.
#[derive(Debug, Clone, Deserialize)]
pub struct VllmCompletionResponse {
    /// Unique response identifier.
    pub id: String,
    /// Object type — `"text_completion"`.
    pub object: String,
    /// Unix timestamp of generation.
    pub created: u64,
    /// Model that produced this response.
    pub model: String,
    /// Ranked completion choices.
    pub choices: Vec<VllmChoice>,
    /// Token usage statistics (absent in streaming chunks).
    #[serde(default)]
    pub usage: Option<VllmUsage>,
}

// ---------------------------------------------------------------------------
// Chat completion types
// ---------------------------------------------------------------------------

/// A single message in a chat conversation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VllmChatMessage {
    /// Role of the message author (`"system"`, `"user"`, or `"assistant"`).
    pub role: String,
    /// Message content.
    pub content: String,
}

/// A single choice in a chat completion response.
#[derive(Debug, Clone, Deserialize)]
pub struct VllmChatChoice {
    /// The generated message.
    pub message: VllmChatMessage,
    /// Index of this choice in the list.
    pub index: u32,
    /// Reason generation stopped — `None` in streaming chunks.
    #[serde(default)]
    pub finish_reason: Option<String>,
}

/// Request body for `POST /v1/chat/completions`.
#[derive(Debug, Clone, Serialize)]
pub struct VllmChatCompletionRequest {
    /// Model name as known to the vLLM server.
    pub model: String,
    /// Conversation messages (system, user, assistant).
    pub messages: Vec<VllmChatMessage>,
    /// Maximum number of tokens to generate.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_tokens: Option<u32>,
    /// Sampling temperature.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub temperature: Option<f32>,
    /// Nucleus sampling probability.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub top_p: Option<f32>,
    /// Stream partial progress as SSE events.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stream: Option<bool>,
    /// Stop sequences.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stop: Option<Vec<String>>,
}

impl VllmChatCompletionRequest {
    /// Create a minimal chat completion request with a model and messages.
    #[must_use]
    pub fn new(model: impl Into<String>, messages: Vec<VllmChatMessage>) -> Self {
        Self {
            model: model.into(),
            messages,
            max_tokens: None,
            temperature: None,
            top_p: None,
            stream: None,
            stop: None,
        }
    }

    /// Set the maximum number of tokens to generate.
    #[must_use]
    pub fn with_max_tokens(mut self, max_tokens: u32) -> Self {
        self.max_tokens = Some(max_tokens);
        self
    }

    /// Set the sampling temperature.
    #[must_use]
    pub fn with_temperature(mut self, temperature: f32) -> Self {
        self.temperature = Some(temperature);
        self
    }
}

/// Response body from `POST /v1/chat/completions`.
#[derive(Debug, Clone, Deserialize)]
pub struct VllmChatCompletionResponse {
    /// Unique response identifier.
    pub id: String,
    /// Object type — `"chat.completion"`.
    pub object: String,
    /// Unix timestamp of generation.
    pub created: u64,
    /// Model that produced this response.
    pub model: String,
    /// Ranked chat completion choices.
    pub choices: Vec<VllmChatChoice>,
    /// Token usage statistics (absent in streaming chunks).
    #[serde(default)]
    pub usage: Option<VllmUsage>,
}

// ---------------------------------------------------------------------------
// Model listing types
// ---------------------------------------------------------------------------

/// A single model entry from `GET /v1/models`.
#[derive(Debug, Clone, Deserialize)]
pub struct VllmModelInfo {
    /// Model identifier (e.g. `"meta-llama/Llama-3.1-8B-Instruct"`).
    pub id: String,
    /// Object type — `"model"`.
    pub object: String,
    /// Unix timestamp of model creation.
    pub created: u64,
    /// Organization that owns the model.
    pub owned_by: String,
}

/// Intermediate deserialisation target for `GET /v1/models`.
#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code, reason = "serde deserialisation-only struct")]
struct VllmModelListResponse {
    #[allow(dead_code, reason = "serde deserialisation-only field")]
    object: String,
    data: Vec<VllmModelInfo>,
}

// ---------------------------------------------------------------------------
// Adapter
// ---------------------------------------------------------------------------

/// Typed HTTP client for a vLLM inference server.
///
/// Wraps a [`reqwest::Client`] configured with a per-request timeout.
/// Optionally carries a [`CognitiveEvidenceEmitter`] that records
/// `MODEL_CALL` receipts on every `complete()` invocation.
///
/// The vLLM server exposes an **OpenAI-compatible API** — the adapter
/// speaks to the standard `/v1/completions`, `/v1/chat/completions`,
/// and `/v1/models` endpoints.
#[derive(Clone)]
pub struct VllmAdapter {
    base_url: String,
    client: reqwest::Client,
    timeout_seconds: u64,
    evidence_emitter: Option<Arc<CognitiveEvidenceEmitter>>,
}

impl std::fmt::Debug for VllmAdapter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VllmAdapter")
            .field("base_url", &self.base_url)
            .field("client", &"<reqwest::Client>")
            .field("timeout_seconds", &self.timeout_seconds)
            .field("evidence_emitter", &self.evidence_emitter.is_some())
            .finish()
    }
}

impl VllmAdapter {
    /// Create an adapter targeting `base_url` (e.g. `"http://localhost:8000"`).
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
    /// receipts on every `complete()` call.
    #[must_use]
    pub fn with_evidence_emitter(mut self, emitter: Arc<CognitiveEvidenceEmitter>) -> Self {
        self.evidence_emitter = Some(emitter);
        self
    }

    /// Send a non-streaming completion request to `POST /v1/completions`.
    ///
    /// Forces `stream` to `false` regardless of what was set on the request.
    /// If an evidence emitter is attached, emits a `MODEL_CALL` receipt
    /// after a successful response.
    ///
    /// # Errors
    ///
    /// - [`VllmError::ConnectionFailed`] — server unreachable.
    /// - [`VllmError::Timeout`] — request exceeded the configured timeout.
    /// - [`VllmError::ModelNotFound`] — HTTP 404 from the server.
    /// - [`VllmError::ParseError`] — response body is not valid JSON.
    pub async fn complete(
        &self,
        request: VllmCompletionRequest,
    ) -> Result<VllmCompletionResponse, VllmError> {
        let mut req = request;
        req.stream = Some(false);

        let start = Instant::now();

        let response = self
            .client
            .post(format!("{}/v1/completions", self.base_url))
            .json(&req)
            .send()
            .await
            .map_err(|e| {
                if e.is_timeout() {
                    VllmError::Timeout
                } else {
                    VllmError::ConnectionFailed(e.to_string())
                }
            })?;

        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(match status.as_u16() {
                404 => VllmError::ModelNotFound(body),
                _ => VllmError::UnexpectedResponse(format!("HTTP {status}: {body}")),
            });
        }

        let parsed: VllmCompletionResponse = response.json().await.map_err(|e| {
            if e.is_timeout() {
                VllmError::Timeout
            } else {
                VllmError::ParseError(e.to_string())
            }
        })?;

        let latency_ms = start.elapsed().as_millis() as u64;

        if let Some(ref emitter) = self.evidence_emitter {
            let usage = parsed.usage.as_ref();
            let tokens_in = usage.map_or(0, |u| u.prompt_tokens);
            let tokens_out = usage.map_or(0, |u| u.completion_tokens);
            let _ = emitter
                .emit_model_call(&req.model, &req.model, tokens_in, tokens_out, 0, latency_ms)
                .await;
        }

        Ok(parsed)
    }

    /// Send a chat completion request to `POST /v1/chat/completions`.
    ///
    /// Forces `stream` to `false`. If an evidence emitter is attached,
    /// emits a `MODEL_CALL` receipt after a successful response.
    ///
    /// # Errors
    ///
    /// - [`VllmError::ConnectionFailed`] — server unreachable.
    /// - [`VllmError::Timeout`] — request exceeded the configured timeout.
    /// - [`VllmError::ModelNotFound`] — HTTP 404 from the server.
    /// - [`VllmError::ParseError`] — response body is not valid JSON.
    pub async fn chat(
        &self,
        request: VllmChatCompletionRequest,
    ) -> Result<VllmChatCompletionResponse, VllmError> {
        let mut req = request;
        req.stream = Some(false);

        let start = Instant::now();

        let response = self
            .client
            .post(format!("{}/v1/chat/completions", self.base_url))
            .json(&req)
            .send()
            .await
            .map_err(|e| {
                if e.is_timeout() {
                    VllmError::Timeout
                } else {
                    VllmError::ConnectionFailed(e.to_string())
                }
            })?;

        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(match status.as_u16() {
                404 => VllmError::ModelNotFound(body),
                _ => VllmError::UnexpectedResponse(format!("HTTP {status}: {body}")),
            });
        }

        let parsed: VllmChatCompletionResponse = response.json().await.map_err(|e| {
            if e.is_timeout() {
                VllmError::Timeout
            } else {
                VllmError::ParseError(e.to_string())
            }
        })?;

        let latency_ms = start.elapsed().as_millis() as u64;

        if let Some(ref emitter) = self.evidence_emitter {
            let usage = parsed.usage.as_ref();
            let tokens_in = usage.map_or(0, |u| u.prompt_tokens);
            let tokens_out = usage.map_or(0, |u| u.completion_tokens);
            let _ = emitter
                .emit_model_call(&req.model, &req.model, tokens_in, tokens_out, 0, latency_ms)
                .await;
        }

        Ok(parsed)
    }

    /// Send a streaming completion request to `POST /v1/completions`.
    ///
    /// Forces `stream` to `true`. Returns a [`Stream`] of partial
    /// [`VllmCompletionResponse`] objects. The server uses SSE
    /// (`data: {...}\n\n`) as the wire format; the final event carries
    /// a `finish_reason` and `usage` payload.
    ///
    /// The returned stream is `'static` and `Send` — it can be spawned on
    /// a tokio task. The full response body is buffered in memory before
    /// the first chunk is yielded.
    ///
    /// # Errors
    ///
    /// - [`VllmError::ConnectionFailed`] — server unreachable.
    /// - [`VllmError::Timeout`] — request exceeded the configured timeout.
    /// - [`VllmError::ModelNotFound`] — HTTP 404 from the server.
    /// - [`VllmError::StreamingError`] — failed to read the response body.
    pub async fn complete_stream(
        &self,
        request: VllmCompletionRequest,
    ) -> Result<
        impl Stream<Item = Result<VllmCompletionResponse, VllmError>> + Send + 'static,
        VllmError,
    > {
        let mut req = request;
        req.stream = Some(true);

        let response = self
            .client
            .post(format!("{}/v1/completions", self.base_url))
            .json(&req)
            .send()
            .await
            .map_err(|e| {
                if e.is_timeout() {
                    VllmError::Timeout
                } else {
                    VllmError::ConnectionFailed(e.to_string())
                }
            })?;

        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(match status.as_u16() {
                404 => VllmError::ModelNotFound(body),
                _ => VllmError::UnexpectedResponse(format!("HTTP {status}: {body}")),
            });
        }

        let body = response
            .text()
            .await
            .map_err(|e| VllmError::StreamingError(e.to_string()))?;

        let results: Vec<Result<VllmCompletionResponse, VllmError>> = parse_sse_stream(&body);

        Ok(futures::stream::iter(results))
    }

    /// List all models known to the vLLM server via `GET /v1/models`.
    ///
    /// # Errors
    ///
    /// - [`VllmError::ConnectionFailed`] — server unreachable.
    /// - [`VllmError::Timeout`] — request exceeded the configured timeout.
    /// - [`VllmError::UnexpectedResponse`] — non-success HTTP status.
    /// - [`VllmError::ParseError`] — response body is not valid JSON.
    pub async fn list_models(&self) -> Result<Vec<VllmModelInfo>, VllmError> {
        let response = self
            .client
            .get(format!("{}/v1/models", self.base_url))
            .send()
            .await
            .map_err(|e| {
                if e.is_timeout() {
                    VllmError::Timeout
                } else {
                    VllmError::ConnectionFailed(e.to_string())
                }
            })?;

        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(VllmError::UnexpectedResponse(format!(
                "HTTP {status}: {body}"
            )));
        }

        let parsed: VllmModelListResponse = response.json().await.map_err(|e| {
            if e.is_timeout() {
                VllmError::Timeout
            } else {
                VllmError::ParseError(e.to_string())
            }
        })?;

        Ok(parsed.data)
    }

    /// Ping the vLLM server health endpoint (`GET /health`) to check liveness.
    ///
    /// Returns `Ok(true)` when the server responds with a success status.
    /// Returns `Ok(false)` when the connection is refused or times out
    /// (server is down but no internal error occurred).
    ///
    /// # Errors
    ///
    /// Returns [`VllmError::ConnectionFailed`] only for unexpected
    /// transport errors that are not connection-refused or timeout.
    pub async fn health_check(&self) -> Result<bool, VllmError> {
        match self
            .client
            .get(format!("{}/health", self.base_url))
            .send()
            .await
        {
            Ok(response) => Ok(response.status().is_success()),
            Err(e) => {
                if e.is_connect() || e.is_timeout() {
                    Ok(false)
                } else {
                    Err(VllmError::ConnectionFailed(e.to_string()))
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

// ---------------------------------------------------------------------------
// SSE stream parser
// ---------------------------------------------------------------------------

/// Parse a vLLM SSE (`text/event-stream`) body into a collection of
/// parsed response chunks.
///
/// Each SSE event has the form `data: <json>\n\n`. The final event is
/// `data: [DONE]\n\n` which signals end-of-stream but carries no JSON.
fn parse_sse_stream(body: &str) -> Vec<Result<VllmCompletionResponse, VllmError>> {
    body.split("\n\n")
        .filter_map(|event| {
            let trimmed = event.trim();
            if trimmed.is_empty() {
                return None;
            }
            for line in trimmed.lines() {
                let line = line.trim();
                if let Some(payload) = line.strip_prefix("data: ") {
                    let payload = payload.trim();
                    if payload == "[DONE]" {
                        return None;
                    }
                    return Some(
                        serde_json::from_str::<VllmCompletionResponse>(payload)
                            .map_err(|e| VllmError::ParseError(e.to_string())),
                    );
                }
            }
            None
        })
        .collect()
}

// ===========================================================================
// Tests
// ===========================================================================

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

    fn test_adapter() -> VllmAdapter {
        VllmAdapter::new("http://localhost:8000", 30)
    }

    // -----------------------------------------------------------------------
    // Serialisation / deserialisation tests
    // -----------------------------------------------------------------------

    #[test]
    fn serialize_completion_request_defaults() {
        let req = VllmCompletionRequest::new("meta-llama/Llama-3.1-8B", "Once upon a time");
        let json = serde_json::to_value(&req).unwrap();

        assert_eq!(json["model"], "meta-llama/Llama-3.1-8B");
        assert_eq!(json["prompt"], "Once upon a time");
        assert!(json.get("stream").is_none());
        assert!(json.get("max_tokens").is_none());
    }

    #[test]
    fn serialize_completion_request_with_all_options() {
        let req = VllmCompletionRequest::new("llama-8b", "hello")
            .with_max_tokens(256)
            .with_temperature(0.7)
            .with_top_p(0.9)
            .with_stop(vec!["END".into(), "STOP".into()]);

        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["max_tokens"], 256);
        assert!((json["temperature"].as_f64().unwrap() - 0.7_f64).abs() < 0.001);
        assert!((json["top_p"].as_f64().unwrap() - 0.9_f64).abs() < 0.001);
        let stop = json["stop"].as_array().unwrap();
        assert_eq!(stop.len(), 2);
        assert_eq!(stop[0], "END");
        assert_eq!(stop[1], "STOP");
    }

    #[test]
    fn deserialize_complete_completion_response() {
        let raw = r#"{
            "id": "cmpl-abc123",
            "object": "text_completion",
            "created": 1700000000,
            "model": "meta-llama/Llama-3.1-8B",
            "choices": [
                {
                    "text": "The sky is blue because of Rayleigh scattering.",
                    "index": 0,
                    "finish_reason": "stop"
                }
            ],
            "usage": {
                "prompt_tokens": 12,
                "completion_tokens": 9,
                "total_tokens": 21
            }
        }"#;

        let parsed: VllmCompletionResponse =
            serde_json::from_str(raw).expect("deserialize complete response");

        assert_eq!(parsed.id, "cmpl-abc123");
        assert_eq!(parsed.object, "text_completion");
        assert_eq!(parsed.model, "meta-llama/Llama-3.1-8B");
        assert_eq!(parsed.choices.len(), 1);
        assert_eq!(
            parsed.choices[0].text,
            "The sky is blue because of Rayleigh scattering."
        );
        assert_eq!(parsed.choices[0].index, 0);
        assert_eq!(parsed.choices[0].finish_reason.as_deref(), Some("stop"));
        let usage = parsed.usage.expect("usage present");
        assert_eq!(usage.prompt_tokens, 12);
        assert_eq!(usage.completion_tokens, 9);
        assert_eq!(usage.total_tokens, 21);
    }

    #[test]
    fn deserialize_completion_response_multiple_choices() {
        let raw = r#"{
            "id": "cmpl-xyz",
            "object": "text_completion",
            "created": 1700000001,
            "model": "gpt-4",
            "choices": [
                {"text": "first", "index": 0, "finish_reason": "length"},
                {"text": "second", "index": 1, "finish_reason": "length"}
            ],
            "usage": {"prompt_tokens": 5, "completion_tokens": 10, "total_tokens": 15}
        }"#;

        let parsed: VllmCompletionResponse =
            serde_json::from_str(raw).expect("deserialize multi-choice");

        assert_eq!(parsed.choices.len(), 2);
        assert_eq!(parsed.choices[0].text, "first");
        assert_eq!(parsed.choices[1].text, "second");
    }

    #[test]
    fn deserialize_completion_response_no_usage() {
        let raw = r#"{
            "id": "cmpl-stream-chunk",
            "object": "text_completion",
            "created": 1700000002,
            "model": "llama-8b",
            "choices": [{"text": "partial", "index": 0}]
        }"#;

        let parsed: VllmCompletionResponse =
            serde_json::from_str(raw).expect("deserialize without usage");

        assert!(parsed.usage.is_none());
        assert_eq!(parsed.choices[0].text, "partial");
        assert!(parsed.choices[0].finish_reason.is_none());
    }

    #[test]
    fn serialize_chat_completion_request() {
        let messages = vec![
            VllmChatMessage {
                role: "system".into(),
                content: "You are a helpful assistant.".into(),
            },
            VllmChatMessage {
                role: "user".into(),
                content: "What is Rust?".into(),
            },
        ];
        let req = VllmChatCompletionRequest::new("llama-8b", messages)
            .with_max_tokens(512)
            .with_temperature(0.3);

        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["model"], "llama-8b");
        let msgs = json["messages"].as_array().unwrap();
        assert_eq!(msgs.len(), 2);
        assert_eq!(msgs[0]["role"], "system");
        assert_eq!(msgs[0]["content"], "You are a helpful assistant.");
        assert_eq!(msgs[1]["role"], "user");
        assert_eq!(json["max_tokens"], 512);
        assert!((json["temperature"].as_f64().unwrap() - 0.3_f64).abs() < 0.001);
    }

    #[test]
    fn deserialize_chat_completion_response() {
        let raw = r#"{
            "id": "chatcmpl-abc123",
            "object": "chat.completion",
            "created": 1700000003,
            "model": "meta-llama/Llama-3.1-8B",
            "choices": [
                {
                    "message": {
                        "role": "assistant",
                        "content": "Rust is a systems programming language."
                    },
                    "index": 0,
                    "finish_reason": "stop"
                }
            ],
            "usage": {
                "prompt_tokens": 20,
                "completion_tokens": 8,
                "total_tokens": 28
            }
        }"#;

        let parsed: VllmChatCompletionResponse =
            serde_json::from_str(raw).expect("deserialize chat response");

        assert_eq!(parsed.id, "chatcmpl-abc123");
        assert_eq!(parsed.object, "chat.completion");
        assert_eq!(parsed.choices.len(), 1);
        assert_eq!(parsed.choices[0].message.role, "assistant");
        assert!(parsed.choices[0]
            .message
            .content
            .contains("systems programming"));
        assert_eq!(parsed.choices[0].finish_reason.as_deref(), Some("stop"));
        let usage = parsed.usage.expect("usage present");
        assert_eq!(usage.prompt_tokens, 20);
        assert_eq!(usage.completion_tokens, 8);
        assert_eq!(usage.total_tokens, 28);
    }

    #[test]
    fn deserialize_model_list_response() {
        let raw = r#"{
            "object": "list",
            "data": [
                {
                    "id": "meta-llama/Llama-3.1-8B-Instruct",
                    "object": "model",
                    "created": 1721692800,
                    "owned_by": "meta-llama"
                },
                {
                    "id": "mistralai/Mistral-7B-Instruct-v0.3",
                    "object": "model",
                    "created": 1714003200,
                    "owned_by": "mistralai"
                }
            ]
        }"#;

        let parsed: VllmModelListResponse =
            serde_json::from_str(raw).expect("deserialize model list");

        assert_eq!(parsed.object, "list");
        assert_eq!(parsed.data.len(), 2);
        assert_eq!(parsed.data[0].id, "meta-llama/Llama-3.1-8B-Instruct");
        assert_eq!(parsed.data[0].owned_by, "meta-llama");
        assert_eq!(parsed.data[1].id, "mistralai/Mistral-7B-Instruct-v0.3");
        assert_eq!(parsed.data[1].owned_by, "mistralai");
    }

    // -----------------------------------------------------------------------
    // SSE streaming parse tests
    // -----------------------------------------------------------------------

    #[test]
    fn parse_sse_stream_single_chunk() {
        let body = r#"data: {"id":"cmpl-1","object":"text_completion","created":1700000000,"model":"llama","choices":[{"text":"hello","index":0,"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}

data: [DONE]
"#;

        let results: Vec<VllmCompletionResponse> = parse_sse_stream(body)
            .into_iter()
            .map(|r| r.expect("parse ok"))
            .collect();

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].id, "cmpl-1");
        assert_eq!(results[0].choices[0].text, "hello");
        assert_eq!(results[0].choices[0].finish_reason.as_deref(), Some("stop"));
    }

    #[test]
    fn parse_sse_stream_multiple_chunks_yields_correct_accumulation() {
        let body = "data: {\"id\":\"cmpl-1\",\"object\":\"text_completion\",\"created\":1700000000,\"model\":\"llama\",\"choices\":[{\"text\":\"The\",\"index\":0}]}\n\
                     \n\
                     data: {\"id\":\"cmpl-1\",\"object\":\"text_completion\",\"created\":1700000000,\"model\":\"llama\",\"choices\":[{\"text\":\" sky\",\"index\":0}]}\n\
                     \n\
                     data: {\"id\":\"cmpl-1\",\"object\":\"text_completion\",\"created\":1700000000,\"model\":\"llama\",\"choices\":[{\"text\":\" is\",\"index\":0}]}\n\
                     \n\
                     data: {\"id\":\"cmpl-1\",\"object\":\"text_completion\",\"created\":1700000000,\"model\":\"llama\",\"choices\":[{\"text\":\" blue\",\"index\":0,\"finish_reason\":\"stop\"}],\"usage\":{\"prompt_tokens\":2,\"completion_tokens\":4,\"total_tokens\":6}}\n\
                     \n\
                     data: [DONE]\n";

        let results: Vec<VllmCompletionResponse> = parse_sse_stream(body)
            .into_iter()
            .map(|r| r.expect("parse ok"))
            .collect();

        assert_eq!(results.len(), 4);

        let full_text: String = results.iter().map(|r| r.choices[0].text.as_str()).collect();
        assert_eq!(full_text, "The sky is blue");

        assert!(results[0].choices[0].finish_reason.is_none());
        assert!(results[3].choices[0].finish_reason.as_deref() == Some("stop"));
        assert!(results[3].usage.is_some());
    }

    #[test]
    fn parse_sse_stream_empty_body_yields_empty_vec() {
        let results = parse_sse_stream("");
        assert!(results.is_empty());
    }

    #[test]
    fn parse_sse_stream_only_done_yields_empty_vec() {
        let results = parse_sse_stream("data: [DONE]\n\n");
        assert!(results.is_empty());
    }

    #[test]
    fn parse_sse_stream_malformed_json_yields_parse_error() {
        let body = "data: not valid json\n\ndata: [DONE]\n";
        let results = parse_sse_stream(body);
        assert_eq!(results.len(), 1);
        assert!(matches!(results[0], Err(VllmError::ParseError(_))));
    }

    #[test]
    fn parse_sse_stream_handles_extra_spaces() {
        let body = "  data: {\"id\":\"x\",\"object\":\"text_completion\",\"created\":1,\"model\":\"m\",\"choices\":[{\"text\":\"ok\",\"index\":0}]}\n\n";
        let results: Vec<_> = parse_sse_stream(body)
            .into_iter()
            .map(|r| r.unwrap())
            .collect();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].choices[0].text, "ok");
    }

    // -----------------------------------------------------------------------
    // VllmError tests
    // -----------------------------------------------------------------------

    #[test]
    fn error_displays_meaningful_message() {
        let err = VllmError::ConnectionFailed("refused".into());
        assert!(err.to_string().contains("refused"));

        let err = VllmError::ModelNotFound("unknown model".into());
        assert!(err.to_string().contains("unknown model"));

        let err = VllmError::Timeout;
        assert!(err.to_string().contains("timed out"));
    }

    // -----------------------------------------------------------------------
    // Adapter construction tests
    // -----------------------------------------------------------------------

    #[test]
    fn adapter_constructs_with_custom_timeout() {
        let adapter = VllmAdapter::new("http://localhost:8000", 60);
        assert_eq!(adapter.base_url(), "http://localhost:8000");
        assert_eq!(adapter.timeout_seconds(), 60);
    }

    #[test]
    fn adapter_debug_does_not_leak_client() {
        let adapter = test_adapter();
        let debug_str = format!("{adapter:?}");
        assert!(debug_str.contains("VllmAdapter"));
        assert!(debug_str.contains("<reqwest::Client>"), "client is opaque");
    }

    // -----------------------------------------------------------------------
    // Connection error test (no server running)
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn complete_connection_refused_returns_error() {
        let adapter = VllmAdapter::new("http://127.0.0.1:19998", 1);

        let req = VllmCompletionRequest::new("llama", "hello");
        let result = adapter.complete(req).await;

        assert!(result.is_err(), "should fail with no server");
        match result {
            Err(VllmError::ConnectionFailed(_) | VllmError::Timeout) => {}
            other => panic!("expected ConnectionFailed or Timeout, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn health_check_returns_false_when_no_server() {
        let adapter = VllmAdapter::new("http://127.0.0.1:19998", 1);
        let healthy = adapter.health_check().await;
        assert!(
            matches!(healthy, Ok(false)),
            "expected Ok(false) with no server, got {healthy:?}"
        );
    }

    // -----------------------------------------------------------------------
    // Streaming accumulation test (parse SSE lines from memory)
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn stream_items_yield_correct_token_accumulation() {
        let sse_events: Vec<Result<VllmCompletionResponse, VllmError>> =
            futures::stream::iter([
                r#"{"id":"cmpl-1","object":"text_completion","created":1700000000,"model":"llama","choices":[{"text":"The","index":0}]}"#,
                r#"{"id":"cmpl-1","object":"text_completion","created":1700000000,"model":"llama","choices":[{"text":" sky","index":0}]}"#,
                r#"{"id":"cmpl-1","object":"text_completion","created":1700000000,"model":"llama","choices":[{"text":" is","index":0}]}"#,
                r#"{"id":"cmpl-1","object":"text_completion","created":1700000000,"model":"llama","choices":[{"text":" blue","index":0,"finish_reason":"stop"}],"usage":{"prompt_tokens":2,"completion_tokens":4,"total_tokens":6}}"#,
            ])
            .filter_map(|raw| async {
                match serde_json::from_str::<VllmCompletionResponse>(raw) {
                    Ok(resp) => Some(Ok(resp)),
                    Err(e) => Some(Err(VllmError::ParseError(e.to_string()))),
                }
            })
            .collect()
            .await;

        let results: Vec<VllmCompletionResponse> = sse_events
            .into_iter()
            .map(|r| r.expect("parse ok"))
            .collect();

        assert_eq!(results.len(), 4);
        assert!(results[0].choices[0].finish_reason.is_none());
        assert!(results[3].choices[0].finish_reason.as_deref() == Some("stop"));
        assert_eq!(results[3].usage.as_ref().unwrap().completion_tokens, 4);

        let full_text: String = results.iter().map(|r| r.choices[0].text.as_str()).collect();
        assert_eq!(full_text, "The sky is blue");
    }

    // -----------------------------------------------------------------------
    // VllmCompletionRequest builder chain
    // -----------------------------------------------------------------------

    #[test]
    fn request_builder_chain() {
        let req = VllmCompletionRequest::new("mistral", "hi")
            .with_max_tokens(100)
            .with_temperature(0.5)
            .with_top_p(0.8)
            .with_stop(vec!["<|end|>".into()]);

        assert_eq!(req.model, "mistral");
        assert_eq!(req.prompt, "hi");
        assert_eq!(req.max_tokens, Some(100));
        assert_eq!(req.temperature, Some(0.5));
        assert_eq!(req.top_p, Some(0.8));
        assert_eq!(req.stop, Some(vec!["<|end|>".into()]));
    }
}
