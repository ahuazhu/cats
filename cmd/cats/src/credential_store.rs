#[cfg(test)]
use anyhow::Context as _;
use anyhow::Result;

#[cfg(target_os = "macos")]
mod platform {
    use std::io::Write;
    use std::process::{Command, Output, Stdio};
    use std::thread;
    use std::time::{Duration, Instant};

    use anyhow::{bail, ensure, Context, Result};
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;

    const SECURITY: &str = "/usr/bin/security";
    const ENCODING_PREFIX: &str = "cats-keyring-base64:";
    const MAX_INTERACTIVE_COMMAND_BYTES: usize = 4096;
    const COMMAND_TIMEOUT: Duration = Duration::from_secs(60);
    const POLL_INTERVAL: Duration = Duration::from_millis(25);
    const SET_SECURITY_ARGS: [&str; 1] = ["-i"];

    pub(super) fn get(service: &str, account: &str) -> Result<Option<String>> {
        let output = run_security(
            "read Cats login",
            &["find-generic-password", "-s", service, "-wa", account],
            None,
            true,
        )?;
        if item_not_found(&output) {
            return Ok(None);
        }
        ensure_success("read Cats login from macOS Keychain", &output)?;

        let stored = String::from_utf8(output.stdout)
            .context("Cats login in macOS Keychain is not valid UTF-8")?;
        decode_secret(stored.trim_end_matches(['\r', '\n']))
            .map(Some)
            .context("decode Cats login from macOS Keychain")
    }

    pub(super) fn set(service: &str, account: &str, secret: &str) -> Result<()> {
        let stored = format!("{ENCODING_PREFIX}{}", STANDARD.encode(secret));
        let command = add_command(service, account, &stored)?;
        let output = run_security(
            "save Cats login",
            &SET_SECURITY_ARGS,
            Some(command.as_bytes()),
            false,
        )?;
        ensure_success("save Cats login in macOS Keychain", &output)
    }

    pub(super) fn delete(service: &str, account: &str) -> Result<()> {
        let output = run_security(
            "delete Cats login",
            &["delete-generic-password", "-s", service, "-a", account],
            None,
            true,
        )?;
        if item_not_found(&output) {
            return Ok(());
        }
        ensure_success("delete Cats login from macOS Keychain", &output)
    }

    fn run_security(
        action: &str,
        args: &[&str],
        input: Option<&[u8]>,
        capture_output: bool,
    ) -> Result<Output> {
        let mut command = Command::new(SECURITY);
        command
            .args(args)
            .stdin(if input.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(if capture_output {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stderr(if capture_output {
                Stdio::piped()
            } else {
                Stdio::null()
            });
        let mut child = command
            .spawn()
            .with_context(|| format!("{action}: start {SECURITY}"))?;

        if let Some(input) = input {
            let write_result = child
                .stdin
                .take()
                .context("macOS security process has no stdin")
                .and_then(|mut stdin| {
                    stdin
                        .write_all(input)
                        .context("write to macOS security process")
                });
            if let Err(error) = write_result {
                let _ = child.kill();
                let _ = child.wait();
                return Err(error).with_context(|| action.to_owned());
            }
        }

        let started = Instant::now();
        loop {
            if child
                .try_wait()
                .with_context(|| format!("{action}: wait for {SECURITY}"))?
                .is_some()
            {
                return child
                    .wait_with_output()
                    .with_context(|| format!("{action}: collect output from {SECURITY}"));
            }
            if started.elapsed() >= COMMAND_TIMEOUT {
                let _ = child.kill();
                let _ = child.wait();
                bail!("{action} timed out after 60 seconds");
            }
            thread::sleep(POLL_INTERVAL);
        }
    }

    fn add_command(service: &str, account: &str, stored: &str) -> Result<String> {
        ensure_safe_interactive_value("service", service)?;
        ensure_safe_interactive_value("account", account)?;
        ensure_safe_interactive_value("credential", stored)?;
        let command = format!(
            "add-generic-password -U -s {} -a {} -w {}\n",
            shell_quote(service),
            shell_quote(account),
            shell_quote(stored)
        );
        ensure!(
            command.len() <= MAX_INTERACTIVE_COMMAND_BYTES,
            "Cats login is too large for the macOS Keychain command"
        );
        Ok(command)
    }

    fn ensure_safe_interactive_value(name: &str, value: &str) -> Result<()> {
        ensure!(
            !value.contains(['\0', '\r', '\n']),
            "macOS Keychain {name} contains an unsupported control character"
        );
        Ok(())
    }

    fn shell_quote(value: &str) -> String {
        format!("'{}'", value.replace('\'', "'\\''"))
    }

    fn decode_secret(stored: &str) -> Result<String> {
        let Some(encoded) = stored.strip_prefix(ENCODING_PREFIX) else {
            // Credentials created by older Cats builds were stored as raw JSON.
            return Ok(stored.to_owned());
        };
        let bytes = STANDARD
            .decode(encoded)
            .context("invalid base64 credential payload")?;
        String::from_utf8(bytes).context("credential payload is not valid UTF-8")
    }

    fn item_not_found(output: &Output) -> bool {
        output.status.code() == Some(44)
            || String::from_utf8_lossy(&output.stderr).contains("could not be found")
    }

    fn ensure_success(action: &str, output: &Output) -> Result<()> {
        if output.status.success() {
            return Ok(());
        }
        bail!("{action}: {SECURITY} exited with {}", output.status)
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn encoded_secret_round_trips() {
            let secret = r#"{"access_token":"a token","refresh_token":"刷新"}"#;
            let stored = format!("{ENCODING_PREFIX}{}", STANDARD.encode(secret));
            assert_eq!(decode_secret(&stored).unwrap(), secret);
        }

        #[test]
        fn legacy_unencoded_secret_remains_readable() {
            let secret = r#"{"access_token":"legacy"}"#;
            assert_eq!(decode_secret(secret).unwrap(), secret);
        }

        #[test]
        fn add_uses_interactive_mode_without_raw_secret_in_process_arguments() {
            let secret = r#"{"access_token":"secret-value"}"#;
            let stored = format!("{ENCODING_PREFIX}{}", STANDARD.encode(secret));
            let command = add_command("cats.run CLI", "https://cats.run", &stored).unwrap();

            assert!(command.starts_with("add-generic-password -U "));
            assert!(!command.contains("secret-value"));
            assert_eq!(SET_SECURITY_ARGS, ["-i"]);
            assert!(!SET_SECURITY_ARGS.iter().any(|arg| arg.contains(secret)));
        }

        #[test]
        fn interactive_values_are_quoted_and_newlines_are_rejected() {
            let command = add_command("cats' CLI", "https://cats.run", "encoded").unwrap();
            assert!(command.contains("'cats'\\'' CLI'"));
            assert!(add_command("cats", "https://cats.run\nmalicious", "encoded").is_err());
        }
    }
}

#[cfg(not(target_os = "macos"))]
mod platform {
    use anyhow::{Context, Result};

    pub(super) fn get(service: &str, account: &str) -> Result<Option<String>> {
        let entry = keyring::Entry::new(service, account)
            .context("open the operating-system credential store")?;
        match entry.get_password() {
            Ok(value) => Ok(Some(value)),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(error) => Err(error).context("read Cats login from credential store"),
        }
    }

    pub(super) fn set(service: &str, account: &str, secret: &str) -> Result<()> {
        let entry = keyring::Entry::new(service, account)
            .context("open the operating-system credential store")?;
        entry
            .set_password(secret)
            .context("save Cats login in credential store")
    }

    pub(super) fn delete(service: &str, account: &str) -> Result<()> {
        let entry = keyring::Entry::new(service, account)
            .context("open the operating-system credential store")?;
        match entry.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(error) => Err(error).context("delete Cats login from credential store"),
        }
    }
}

pub(crate) fn get(service: &str, account: &str) -> Result<Option<String>> {
    #[cfg(test)]
    if let Some(path) = test_credential_store_path(service, account)? {
        audit_test_operation("get")?;
        return match std::fs::read_to_string(&path) {
            Ok(value) => Ok(Some(value)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error).context("read test credential store"),
        };
    }
    platform::get(service, account)
}

pub(crate) fn set(service: &str, account: &str, secret: &str) -> Result<()> {
    #[cfg(test)]
    if let Some(path) = test_credential_store_path(service, account)? {
        audit_test_operation("set")?;
        let parent = path
            .parent()
            .context("test credential path has no parent")?;
        std::fs::create_dir_all(parent).context("create test credential store")?;
        return std::fs::write(path, secret).context("write test credential store");
    }
    platform::set(service, account, secret)
}

pub(crate) fn delete(service: &str, account: &str) -> Result<()> {
    #[cfg(test)]
    if let Some(path) = test_credential_store_path(service, account)? {
        audit_test_operation("delete")?;
        return match std::fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error).context("delete test credential store"),
        };
    }
    platform::delete(service, account)
}

#[cfg(test)]
fn test_credential_store_path(service: &str, account: &str) -> Result<Option<std::path::PathBuf>> {
    let Some(root) = std::env::var_os("CATS_TEST_CREDENTIAL_STORE_DIR") else {
        return Ok(None);
    };
    let root = std::path::PathBuf::from(root);
    anyhow::ensure!(
        root.is_absolute(),
        "test credential-store directory must be absolute"
    );
    Ok(Some(test_path(&root, service, account)))
}

#[cfg(test)]
pub(crate) fn test_path(
    root: &std::path::Path,
    service: &str,
    account: &str,
) -> std::path::PathBuf {
    use sha2::{Digest as _, Sha256};

    let mut hasher = Sha256::new();
    hasher.update(b"cats.test-credential-store.v1\0");
    hasher.update(service.as_bytes());
    hasher.update([0]);
    hasher.update(account.as_bytes());
    let digest = hasher.finalize();
    let name = digest
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    root.join(name)
}

#[cfg(test)]
fn audit_test_operation(operation: &str) -> Result<()> {
    use std::io::Write as _;

    let Some(path) = std::env::var_os("CATS_TEST_CREDENTIAL_STORE_AUDIT_FILE") else {
        return Ok(());
    };
    let path = std::path::PathBuf::from(path);
    anyhow::ensure!(
        path.is_absolute(),
        "test credential audit path must be absolute"
    );
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .context("open test credential audit")?;
    writeln!(file, "{operation}").context("append test credential audit")
}
