//! One handle for every host process the node agent supervises.
//!
//! A process this agent forked is a `std::process::Child`: it can be waited on
//! and reaped. A process the agent *adopts* — recovered by pid after an agent
//! restart — is not a child of this process, so `waitpid` would fail with
//! `ECHILD` and its exit has to be observed by probing the pid instead. Both
//! kinds appear on the same supervision paths (guest/VMM and `cats-blockd`), so
//! they share one type rather than splitting every call site.
//!
//! This lives at the crate root because both `runtime` and `ch` supervise
//! processes.

use std::process::Child;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};

/// How long [`ProcHandle::kill_and_reap`] waits for an adopted process to
/// disappear. It is not our child, so there is nothing to reap and nothing that
/// guarantees progress; teardown must not block forever on it.
const ADOPTED_EXIT_DEADLINE: Duration = Duration::from_secs(5);
const ADOPTED_EXIT_POLL: Duration = Duration::from_millis(10);

pub(crate) enum ProcHandle {
    /// Forked by this agent, so it can be waited on and reaped.
    Owned(Child),
    /// Recovered by pid after an agent restart. Signals still work; `waitpid`
    /// does not.
    // Constructed by the reattach path that this type is groundwork for, and by
    // this module's tests. Narrowly scoped so the rest of the crate keeps its
    // dead-code coverage.
    #[allow(dead_code)]
    Adopted { pid: u32 },
}

impl ProcHandle {
    pub(crate) fn id(&self) -> u32 {
        match self {
            Self::Owned(child) => child.id(),
            Self::Adopted { pid } => *pid,
        }
    }

    /// Whether the process is gone.
    ///
    /// An owned child is reaped here as a side effect, exactly as `try_wait`
    /// always did. An adopted process is only probed: a zombie it left behind
    /// is its real parent's to reap, and still answers a signal-0 probe.
    pub(crate) fn exited(&mut self) -> Result<bool> {
        match self {
            Self::Owned(child) => Ok(child.try_wait()?.is_some()),
            Self::Adopted { pid } => adopted_exited(*pid),
        }
    }

    /// Terminate the process and leave nothing waitable behind.
    pub(crate) fn kill_and_reap(&mut self) {
        match self {
            Self::Owned(child) => {
                let _ = child.kill();
                let _ = child.wait();
            }
            Self::Adopted { pid } => {
                let pid = *pid;
                signal_pid(pid, libc::SIGKILL);
                let deadline = Instant::now() + ADOPTED_EXIT_DEADLINE;
                while !matches!(adopted_exited(pid), Ok(true)) {
                    if Instant::now() >= deadline {
                        tracing::warn!(pid, "adopted process outlived its SIGKILL deadline");
                        return;
                    }
                    std::thread::sleep(ADOPTED_EXIT_POLL);
                }
            }
        }
    }

    pub(crate) fn signal(&self, sig: i32) {
        signal_pid(self.id(), sig);
    }
}

/// Best-effort `kill(2)`. A process that has already exited answers `ESRCH`,
/// which every caller here treats as success.
fn signal_pid(pid: u32, sig: i32) {
    let Some(pid) = pid_t(pid) else {
        return;
    };
    // SAFETY: `kill` copies both scalar arguments and does not retain any
    // borrowed memory.
    unsafe {
        libc::kill(pid, sig);
    }
}

fn adopted_exited(pid: u32) -> Result<bool> {
    let Some(pid) = pid_t(pid) else {
        // Out of `pid_t` range, so it cannot name a live process.
        return Ok(true);
    };
    // SAFETY: `kill` copies both scalar arguments and does not retain any
    // borrowed memory. Signal 0 delivers nothing and only reports whether the
    // pid could be signalled.
    let rc = unsafe { libc::kill(pid, 0) };
    if rc == 0 {
        return Ok(false);
    }
    let error = std::io::Error::last_os_error();
    match error.raw_os_error() {
        Some(libc::ESRCH) => Ok(true),
        // The pid exists but is owned by someone else: alive, just not ours.
        Some(libc::EPERM) => Ok(false),
        _ => Err(error).with_context(|| format!("probe adopted process {pid}")),
    }
}

fn pid_t(pid: u32) -> Option<libc::pid_t> {
    libc::pid_t::try_from(pid).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    fn spawn_sleeper() -> Child {
        Command::new("sleep")
            .arg("30")
            .spawn()
            .expect("spawn test process")
    }

    /// An adopted pid killed inside this test is still a child of the test
    /// process, so the kernel keeps it as a zombie — and a zombie answers
    /// `kill(pid, 0)` — until its real parent reaps it. In production an adopted
    /// process was reparented to init, which reaps it. Stand in for init.
    fn reap_in_background(mut child: Child) -> std::thread::JoinHandle<()> {
        std::thread::spawn(move || {
            let _ = child.wait();
        })
    }

    fn wait_until_exited(handle: &mut ProcHandle) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while !handle.exited().expect("probe process") {
            assert!(Instant::now() < deadline, "process never exited");
            std::thread::sleep(ADOPTED_EXIT_POLL);
        }
    }

    #[test]
    fn owned_handle_reports_its_child_pid_and_exit() {
        let child = spawn_sleeper();
        let pid = child.id();
        let mut handle = ProcHandle::Owned(child);
        assert_eq!(handle.id(), pid);
        assert!(
            !handle.exited().unwrap(),
            "a fresh sleeper is still running"
        );

        handle.kill_and_reap();
        assert!(handle.exited().unwrap());
    }

    #[test]
    fn adopted_handle_observes_a_process_it_did_not_fork() {
        let child = spawn_sleeper();
        let pid = child.id();
        let mut handle = ProcHandle::Adopted { pid };
        assert_eq!(handle.id(), pid);
        assert!(
            !handle.exited().unwrap(),
            "a live adopted process has not exited"
        );

        let reaper = reap_in_background(child);
        handle.kill_and_reap();
        reaper.join().expect("reaper thread");
        assert!(
            handle.exited().unwrap(),
            "kill_and_reap must terminate an adopted process"
        );
    }

    #[test]
    fn signal_reaches_both_variants() {
        let owned_child = spawn_sleeper();
        let mut owned = ProcHandle::Owned(owned_child);
        owned.signal(libc::SIGKILL);
        wait_until_exited(&mut owned);

        let adopted_child = spawn_sleeper();
        let mut adopted = ProcHandle::Adopted {
            pid: adopted_child.id(),
        };
        let reaper = reap_in_background(adopted_child);
        adopted.signal(libc::SIGKILL);
        reaper.join().expect("reaper thread");
        wait_until_exited(&mut adopted);
    }
}
