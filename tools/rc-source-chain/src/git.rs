use std::{path::Path, process::Command};

use crate::{model::validate_sha, GuardError, GuardResult};

pub(crate) struct GitRepository<'a> {
    root: &'a Path,
}

impl<'a> GitRepository<'a> {
    pub(crate) fn new(root: &'a Path) -> Self {
        Self { root }
    }

    pub(crate) fn resolve_commit(&self, revision: &str) -> GuardResult<String> {
        if revision.starts_with('-') || revision.contains(char::is_whitespace) {
            return Err(GuardError::InvalidRecord(format!(
                "unsafe Git revision {revision:?}"
            )));
        }
        let commit_expression = format!("{revision}^{{commit}}");
        let output = self.run(&["rev-parse", "--verify", &commit_expression])?;
        let sha = output.trim().to_owned();
        validate_sha("resolved Git commit", &sha)?;
        Ok(sha)
    }

    pub(crate) fn is_ancestor(&self, ancestor: &str, descendant: &str) -> GuardResult<bool> {
        let output = Command::new("git")
            .current_dir(self.root)
            .args(["merge-base", "--is-ancestor", ancestor, descendant])
            .output()
            .map_err(GuardError::GitSpawn)?;
        match output.status.code() {
            Some(0) => Ok(true),
            Some(1) => Ok(false),
            _ => Err(GuardError::GitCommand {
                command: format!("git merge-base --is-ancestor {ancestor} {descendant}"),
                stderr: String::from_utf8_lossy(&output.stderr).trim().to_owned(),
            }),
        }
    }

    pub(crate) fn tree(&self, commit: &str) -> GuardResult<String> {
        self.run(&["rev-parse", "--verify", &format!("{commit}^{{tree}}")])
            .map(|output| output.trim().to_owned())
    }

    fn run(&self, arguments: &[&str]) -> GuardResult<String> {
        let output = Command::new("git")
            .current_dir(self.root)
            .args(arguments)
            .output()
            .map_err(GuardError::GitSpawn)?;
        if !output.status.success() {
            return Err(GuardError::GitCommand {
                command: format!("git {}", arguments.join(" ")),
                stderr: String::from_utf8_lossy(&output.stderr).trim().to_owned(),
            });
        }
        String::from_utf8(output.stdout).map_err(GuardError::GitOutput)
    }
}
