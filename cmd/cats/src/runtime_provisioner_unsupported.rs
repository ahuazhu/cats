use anyhow::{bail, Result};

use crate::{Cli, RuntimeProvisionerCommand};

pub(crate) fn run(_cli: &Cli, _command: &RuntimeProvisionerCommand) -> Result<()> {
    bail!("Runtime provisioner artifact tooling requires a Unix platform")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{RuntimeProvisionerCommand, RuntimeProvisionerTrustCommand};
    use clap::Parser as _;

    #[test]
    fn unsupported_boundary_fails_before_file_or_network_io() {
        let cli = Cli::parse_from([
            "cats",
            "admin",
            "runtime-provisioner",
            "trust",
            "verify",
            "--credential-id",
            "provisioner_a",
            "--private-key",
            "missing.pem",
            "--trust-bundle",
            "missing.json",
        ]);
        let command = match &cli.command {
            crate::Command::Admin {
                cmd:
                    crate::AdminCommand::RuntimeProvisioner {
                        cmd:
                            command @ RuntimeProvisionerCommand::Trust {
                                cmd: RuntimeProvisionerTrustCommand::Verify { .. },
                            },
                    },
            } => command,
            other => panic!("unexpected command: {other:?}"),
        };
        assert!(run(&cli, command)
            .unwrap_err()
            .to_string()
            .contains("requires a Unix platform"));
    }
}
