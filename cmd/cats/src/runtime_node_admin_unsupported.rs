//! Controlled fallback for platforms without the crash-safe Runtime Node
//! authority state backend.

use anyhow::{bail, Result};

use crate::{Cli, RuntimeNodeAuthorityAuth, RuntimeNodeCommand};

pub(crate) fn run(
    cli: &Cli,
    _authority: &RuntimeNodeAuthorityAuth<'_>,
    _command: &RuntimeNodeCommand,
) -> Result<()> {
    anyhow::ensure!(
        cli.workspace.is_none(),
        "Runtime Node authority is fleet-scoped, not Workspace-scoped; remove --workspace/CATS_WORKSPACE"
    );
    bail!(
        "Runtime Node authority apply is unavailable on this platform because its \
         crash-safe durable state backend is only implemented on Unix; no request or \
         local authority state was changed"
    )
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    #[test]
    fn runtime_node_authority_fails_before_platform_io() {
        let cli = Cli {
            api_url: Some("https://unreachable.invalid".to_owned()),
            token: None,
            workspace: None,
            json: false,
            command: crate::Command::Admin {
                cmd: crate::AdminCommand::RuntimeNode {
                    deployment_id: None,
                    provisioner_credential_id: None,
                    provisioner_private_key_file: None,
                    cmd: RuntimeNodeCommand::Retire {
                        request: PathBuf::from("must-not-be-read.json"),
                    },
                },
            },
        };
        let authority = RuntimeNodeAuthorityAuth {
            deployment_id: None,
            provisioner_credential_id: None,
            provisioner_private_key_file: None,
        };

        let error = run(
            &cli,
            &authority,
            match &cli.command {
                crate::Command::Admin {
                    cmd: crate::AdminCommand::RuntimeNode { cmd, .. },
                } => cmd,
                _ => unreachable!(),
            },
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("unavailable on this platform"), "{error}");
        assert!(error.contains("no request or local authority state was changed"));
    }
}
