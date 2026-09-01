//! Public Cat exec and interactive-shell wire contracts.
//!
//! Exec is a live, non-idempotent session: callers must never automatically
//! retry a request whose dispatch result is ambiguous. Interactive shell uses
//! JSON text frames for control and binary WebSocket frames for PTY bytes.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Default wall-clock limit for one exec when the caller omits `timeout_ms`.
pub const DEFAULT_EXEC_TIMEOUT_MS: u64 = 120_000;
/// Longest wall-clock limit accepted for one exec.
pub const MAX_EXEC_TIMEOUT_MS: u64 = 3_600_000;
pub const MAX_EXEC_COMMAND_ARGS: usize = 256;
pub const MAX_EXEC_ARGUMENT_BYTES: usize = 16 * 1024;
pub const MAX_EXEC_COMMAND_BYTES: usize = 64 * 1024;
pub const MAX_EXEC_ENV_VARS: usize = 256;
pub const MAX_EXEC_ENV_KEY_BYTES: usize = 256;
pub const MAX_EXEC_ENV_VALUE_BYTES: usize = 16 * 1024;
pub const MAX_EXEC_ENV_BYTES: usize = 64 * 1024;
pub const MAX_EXEC_STDIN_BYTES: usize = 1024 * 1024;
/// Combined UTF-8 stdout and stderr retained for an exec response.
pub const MAX_EXEC_OUTPUT_BYTES: usize = 1024 * 1024;
/// Maximum accepted JSON body after accounting for the historical numeric
/// array encoding of `stdin` plus worst-case JSON string escaping.
pub const MAX_EXEC_JSON_BODY_BYTES: usize = 5 * 1024 * 1024;
/// Maximum Exec response JSON after worst-case escaping of bounded output.
pub const MAX_EXEC_RESPONSE_JSON_BYTES: usize = 7 * 1024 * 1024;

pub const MIN_SHELL_DIMENSION: u16 = 1;
pub const MAX_SHELL_DIMENSION: u16 = 1_000;
/// Caps public and internal WebSocket buffering before PTY data reaches the
/// Guest protocol's own frame bound.
pub const MAX_SHELL_MESSAGE_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecRequest {
    pub command: Vec<String>,
    #[serde(default)]
    pub timeout_ms: Option<u64>,
    /// Environment additions for the child process. Values travel in the
    /// authenticated request body instead of argv, so credentials do not
    /// appear in process listings.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub env: BTreeMap<String, String>,
    /// Optional bytes connected to the child process' standard input.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub stdin: Vec<u8>,
}

impl ExecRequest {
    pub fn validate(&self) -> Result<(), SessionValidationError> {
        if self.command.is_empty() {
            return Err(SessionValidationError::EmptyCommand);
        }
        if self.command.len() > MAX_EXEC_COMMAND_ARGS {
            return Err(SessionValidationError::TooManyArguments);
        }
        let mut command_bytes = 0usize;
        for argument in &self.command {
            let bytes = argument.as_bytes();
            if bytes.len() > MAX_EXEC_ARGUMENT_BYTES {
                return Err(SessionValidationError::ArgumentTooLarge);
            }
            if bytes.contains(&0) {
                return Err(SessionValidationError::ArgumentContainsNul);
            }
            command_bytes = command_bytes.saturating_add(bytes.len());
        }
        if command_bytes > MAX_EXEC_COMMAND_BYTES {
            return Err(SessionValidationError::CommandTooLarge);
        }

        if let Some(timeout_ms) = self.timeout_ms {
            if timeout_ms == 0 || timeout_ms > MAX_EXEC_TIMEOUT_MS {
                return Err(SessionValidationError::InvalidTimeout);
            }
        }

        if self.env.len() > MAX_EXEC_ENV_VARS {
            return Err(SessionValidationError::TooManyEnvironmentVariables);
        }
        let mut env_bytes = 0usize;
        for (name, value) in &self.env {
            let name = name.as_bytes();
            let value = value.as_bytes();
            if name.is_empty()
                || name.len() > MAX_EXEC_ENV_KEY_BYTES
                || name.contains(&0)
                || name.contains(&b'=')
            {
                return Err(SessionValidationError::InvalidEnvironmentName);
            }
            if value.len() > MAX_EXEC_ENV_VALUE_BYTES {
                return Err(SessionValidationError::EnvironmentValueTooLarge);
            }
            if value.contains(&0) {
                return Err(SessionValidationError::EnvironmentValueContainsNul);
            }
            env_bytes = env_bytes
                .saturating_add(name.len())
                .saturating_add(value.len());
        }
        if env_bytes > MAX_EXEC_ENV_BYTES {
            return Err(SessionValidationError::EnvironmentTooLarge);
        }
        if self.stdin.len() > MAX_EXEC_STDIN_BYTES {
            return Err(SessionValidationError::StdinTooLarge);
        }
        Ok(())
    }

    pub fn effective_timeout_ms(&self) -> u64 {
        self.timeout_ms.unwrap_or(DEFAULT_EXEC_TIMEOUT_MS)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecResponse {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
}

impl ExecResponse {
    pub fn validate(&self) -> Result<(), SessionValidationError> {
        if self.stdout.len().saturating_add(self.stderr.len()) > MAX_EXEC_OUTPUT_BYTES {
            return Err(SessionValidationError::OutputTooLarge);
        }
        Ok(())
    }
}

/// JSON control messages carried in WebSocket text frames. PTY input/output
/// uses binary WebSocket frames.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ShellClientControl {
    Resize { rows: u16, cols: u16 },
    Close,
}

impl<'de> Deserialize<'de> for ShellClientControl {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        // Internally tagged unit variants ignore extra fields even under
        // `deny_unknown_fields`. The empty struct form makes Close genuinely
        // closed while preserving its public enum and serialized wire shape.
        #[derive(Deserialize)]
        #[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
        enum StrictShellClientControl {
            Resize { rows: u16, cols: u16 },
            Close {},
        }

        Ok(match StrictShellClientControl::deserialize(deserializer)? {
            StrictShellClientControl::Resize { rows, cols } => Self::Resize { rows, cols },
            StrictShellClientControl::Close {} => Self::Close,
        })
    }
}

impl ShellClientControl {
    pub fn validate(&self) -> Result<(), SessionValidationError> {
        if let Self::Resize { rows, cols } = self {
            if !(MIN_SHELL_DIMENSION..=MAX_SHELL_DIMENSION).contains(rows)
                || !(MIN_SHELL_DIMENSION..=MAX_SHELL_DIMENSION).contains(cols)
            {
                return Err(SessionValidationError::InvalidShellDimensions);
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum ShellServerControl {
    Exit { exit_code: i32 },
    Error { message: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum SessionValidationError {
    #[error("command must be a non-empty argv array")]
    EmptyCommand,
    #[error("command has too many arguments")]
    TooManyArguments,
    #[error("one command argument exceeds the byte limit")]
    ArgumentTooLarge,
    #[error("command arguments may not contain NUL bytes")]
    ArgumentContainsNul,
    #[error("command argv exceeds the aggregate byte limit")]
    CommandTooLarge,
    #[error("timeout_ms must be between 1 and {MAX_EXEC_TIMEOUT_MS}")]
    InvalidTimeout,
    #[error("exec has too many environment variables")]
    TooManyEnvironmentVariables,
    #[error("environment names must be non-empty, bounded, and contain neither '=' nor NUL")]
    InvalidEnvironmentName,
    #[error("one environment value exceeds the byte limit")]
    EnvironmentValueTooLarge,
    #[error("environment values may not contain NUL bytes")]
    EnvironmentValueContainsNul,
    #[error("exec environment exceeds the aggregate byte limit")]
    EnvironmentTooLarge,
    #[error("exec stdin exceeds the byte limit")]
    StdinTooLarge,
    #[error("exec stdout and stderr exceed the combined byte limit")]
    OutputTooLarge,
    #[error("shell rows and cols must each be between 1 and {MAX_SHELL_DIMENSION}")]
    InvalidShellDimensions,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_request() -> ExecRequest {
        ExecRequest {
            command: vec!["/bin/sh".into(), "-c".into(), "printf ok".into()],
            timeout_ms: None,
            env: BTreeMap::new(),
            stdin: Vec::new(),
        }
    }

    #[test]
    fn historical_exec_wire_shape_is_stable() {
        let request: ExecRequest = serde_json::from_value(serde_json::json!({
            "command": ["echo", "hello"]
        }))
        .unwrap();
        assert_eq!(request.timeout_ms, None);
        assert!(request.env.is_empty());
        assert!(request.stdin.is_empty());
        request.validate().unwrap();

        let value = serde_json::to_value(request).unwrap();
        assert_eq!(
            value,
            serde_json::json!({
                "command": ["echo", "hello"],
                "timeout_ms": null
            })
        );
    }

    #[test]
    fn session_wire_rejects_unknown_and_duplicate_fields() {
        assert!(
            serde_json::from_str::<ExecRequest>(r#"{"command":["true"],"unknown":false}"#).is_err()
        );
        assert!(
            serde_json::from_str::<ExecRequest>(r#"{"command":["true"],"command":["false"]}"#)
                .is_err()
        );
        assert!(serde_json::from_str::<ShellClientControl>(
            r#"{"type":"resize","rows":24,"cols":80,"unknown":false}"#
        )
        .is_err());
        assert!(
            serde_json::from_str::<ShellClientControl>(r#"{"type":"close","unknown":false}"#)
                .is_err()
        );
        for duplicate in [
            r#"{"type":"resize","rows":24,"rows":25,"cols":80}"#,
            r#"{"type":"resize","rows":24,"cols":80,"cols":81}"#,
            r#"{"type":"resize","type":"resize","rows":24,"cols":80}"#,
            r#"{"type":"close","type":"close"}"#,
        ] {
            assert!(
                serde_json::from_str::<ShellClientControl>(duplicate).is_err(),
                "accepted duplicate Shell client field in {duplicate}"
            );
        }
    }

    #[test]
    fn exec_rejects_each_untrusted_input_class_at_its_boundary() {
        let mut request = valid_request();
        request.command.clear();
        assert_eq!(
            request.validate(),
            Err(SessionValidationError::EmptyCommand)
        );

        let mut request = valid_request();
        request.timeout_ms = Some(0);
        assert_eq!(
            request.validate(),
            Err(SessionValidationError::InvalidTimeout)
        );

        let mut request = valid_request();
        request.command[0] = "bad\0argv".into();
        assert_eq!(
            request.validate(),
            Err(SessionValidationError::ArgumentContainsNul)
        );

        let mut request = valid_request();
        request.env.insert("BAD=NAME".into(), "value".into());
        assert_eq!(
            request.validate(),
            Err(SessionValidationError::InvalidEnvironmentName)
        );

        let mut request = valid_request();
        request.stdin = vec![0; MAX_EXEC_STDIN_BYTES + 1];
        assert_eq!(
            request.validate(),
            Err(SessionValidationError::StdinTooLarge)
        );
    }

    #[test]
    fn exec_enforces_count_per_field_and_aggregate_limits() {
        let mut request = valid_request();
        request.command = vec!["x".into(); MAX_EXEC_COMMAND_ARGS + 1];
        assert_eq!(
            request.validate(),
            Err(SessionValidationError::TooManyArguments)
        );

        let mut request = valid_request();
        request.command = vec!["x".repeat(MAX_EXEC_ARGUMENT_BYTES + 1)];
        assert_eq!(
            request.validate(),
            Err(SessionValidationError::ArgumentTooLarge)
        );

        let mut request = valid_request();
        request.command = vec!["x".repeat(MAX_EXEC_ARGUMENT_BYTES); 5];
        assert_eq!(
            request.validate(),
            Err(SessionValidationError::CommandTooLarge)
        );

        let mut request = valid_request();
        request.timeout_ms = Some(MAX_EXEC_TIMEOUT_MS + 1);
        assert_eq!(
            request.validate(),
            Err(SessionValidationError::InvalidTimeout)
        );

        let mut request = valid_request();
        request.env = (0..=MAX_EXEC_ENV_VARS)
            .map(|index| (format!("KEY_{index}"), String::new()))
            .collect();
        assert_eq!(
            request.validate(),
            Err(SessionValidationError::TooManyEnvironmentVariables)
        );

        let mut request = valid_request();
        request
            .env
            .insert("KEY".into(), "x".repeat(MAX_EXEC_ENV_VALUE_BYTES + 1));
        assert_eq!(
            request.validate(),
            Err(SessionValidationError::EnvironmentValueTooLarge)
        );

        let mut request = valid_request();
        request.env.insert("KEY".into(), "bad\0value".into());
        assert_eq!(
            request.validate(),
            Err(SessionValidationError::EnvironmentValueContainsNul)
        );

        let mut request = valid_request();
        request.env = (0..5)
            .map(|index| (format!("KEY_{index}"), "x".repeat(MAX_EXEC_ENV_VALUE_BYTES)))
            .collect();
        assert_eq!(
            request.validate(),
            Err(SessionValidationError::EnvironmentTooLarge)
        );
    }

    #[test]
    fn exec_accepts_exact_public_boundaries() {
        let request = ExecRequest {
            command: vec!["x".repeat(MAX_EXEC_ARGUMENT_BYTES); 4],
            timeout_ms: Some(MAX_EXEC_TIMEOUT_MS),
            env: BTreeMap::new(),
            stdin: vec![0; MAX_EXEC_STDIN_BYTES],
        };
        assert_eq!(
            request.command.iter().map(String::len).sum::<usize>(),
            MAX_EXEC_COMMAND_BYTES
        );
        request.validate().unwrap();
    }

    #[test]
    fn encoded_body_caps_cover_worst_case_valid_wire() {
        let request = ExecRequest {
            command: vec!["\u{1}".repeat(MAX_EXEC_ARGUMENT_BYTES); 4],
            timeout_ms: Some(MAX_EXEC_TIMEOUT_MS),
            env: (0..4)
                .map(|index| {
                    (
                        format!("KEY{index}"),
                        "\u{1}".repeat(MAX_EXEC_ENV_VALUE_BYTES - 4),
                    )
                })
                .collect(),
            // 255 is the longest JSON integer representation of one byte.
            stdin: vec![255; MAX_EXEC_STDIN_BYTES],
        };
        request.validate().unwrap();
        assert!(serde_json::to_vec(&request).unwrap().len() <= MAX_EXEC_JSON_BODY_BYTES);

        let response = ExecResponse {
            exit_code: 0,
            // Control characters take the worst-case six-byte JSON escape.
            stdout: "\u{1}".repeat(MAX_EXEC_OUTPUT_BYTES),
            stderr: String::new(),
        };
        response.validate().unwrap();
        assert!(serde_json::to_vec(&response).unwrap().len() <= MAX_EXEC_RESPONSE_JSON_BYTES);
    }

    #[test]
    fn shell_control_wire_is_compatible_and_dimensions_are_bounded() {
        let resize = ShellClientControl::Resize { rows: 24, cols: 80 };
        assert_eq!(
            serde_json::to_value(&resize).unwrap(),
            serde_json::json!({"type":"resize", "rows":24, "cols":80})
        );
        resize.validate().unwrap();
        assert_eq!(
            ShellClientControl::Resize { rows: 0, cols: 80 }.validate(),
            Err(SessionValidationError::InvalidShellDimensions)
        );
        assert_eq!(
            serde_json::to_value(ShellClientControl::Close).unwrap(),
            serde_json::json!({"type":"close"})
        );
        assert_eq!(
            serde_json::to_value(ShellServerControl::Exit { exit_code: 7 }).unwrap(),
            serde_json::json!({"type":"exit", "exit_code":7})
        );
    }

    #[test]
    fn exec_response_output_is_bounded() {
        let valid = ExecResponse {
            exit_code: 0,
            stdout: "x".repeat(MAX_EXEC_OUTPUT_BYTES),
            stderr: String::new(),
        };
        valid.validate().unwrap();
        let invalid = ExecResponse {
            exit_code: 0,
            stdout: "x".repeat(MAX_EXEC_OUTPUT_BYTES),
            stderr: "x".into(),
        };
        assert_eq!(
            invalid.validate(),
            Err(SessionValidationError::OutputTooLarge)
        );
    }
}
