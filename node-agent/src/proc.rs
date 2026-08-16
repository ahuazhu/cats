//! Host process identity and one handle for every process the node agent
//! supervises.
//!
//! A process this agent forked is a `std::process::Child`: it can be waited on
//! and reaped. A process the V1 agent *adopts* by pid after a restart is not a
//! child of this process, so `waitpid` would fail with `ECHILD`; its exit has to
//! be observed by probing the pid instead. Both kinds appear on the same
//! supervision paths (guest/VMM and `cats-blockd`), so they share one type
//! rather than splitting every call site.
//!
//! Identity lives here too, next to the handle it guards: a bare pid proves
//! nothing, because the kernel reuses pids and an adopted process leaves the
//! agent no parent/child relationship to lean on.
//!
//! This lives at the crate root because both `runtime` and `ch` supervise
//! processes.

use std::path::PathBuf;
use std::process::Child;
use std::time::{Duration, Instant};

#[cfg(target_os = "linux")]
use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

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
    ///
    /// The start ticks recorded at adoption travel with the pid on purpose.
    /// Adoption and teardown can be hours apart; an adopted process is not
    /// this agent's child, so the moment it exits the kernel may
    /// hand its pid to something unrelated. Signalling on the pid alone would
    /// then kill a stranger's process, so every signal is re-proved against
    /// this value first. Owned children need no such guard: the kernel reserves
    /// a child's pid until it is reaped.
    Adopted { pid: u32, start_ticks: Option<u64> },
}

impl ProcHandle {
    pub(crate) fn id(&self) -> u32 {
        match self {
            Self::Owned(child) => child.id(),
            Self::Adopted { pid, .. } => *pid,
        }
    }

    /// Whether the process is gone.
    ///
    /// An owned child is reaped here as a side effect, exactly as `try_wait`
    /// always did. An adopted process is only probed: a zombie it left behind
    /// is its real parent's to reap, and still answers a signal-0 probe. A pid
    /// whose start ticks no longer match counts as gone — whatever holds that
    /// pid now, it is not the process this handle names.
    pub(crate) fn exited(&mut self) -> Result<bool> {
        match self {
            Self::Owned(child) => Ok(child.try_wait()?.is_some()),
            Self::Adopted { pid, start_ticks } => {
                if !is_recorded_process(*pid, *start_ticks) {
                    return Ok(true);
                }
                adopted_exited(*pid)
            }
        }
    }

    /// The wait status of an owned child that has already exited.
    ///
    /// `None` for an adopted process: its status went to whoever really
    /// parented it, so there is nothing here to wait for. Only worth asking
    /// after [`Self::exited`] says the process is gone; it exists so a startup
    /// failure can still report *how* a child this agent spawned died, next to
    /// what its log said.
    pub(crate) fn owned_exit_status(&mut self) -> Option<std::process::ExitStatus> {
        match self {
            Self::Owned(child) => child.try_wait().ok().flatten(),
            Self::Adopted { .. } => None,
        }
    }

    /// Terminate the process and leave nothing waitable behind.
    pub(crate) fn kill_and_reap(&mut self) {
        match self {
            Self::Owned(child) => {
                let _ = child.kill();
                let _ = child.wait();
            }
            Self::Adopted { pid, start_ticks } => {
                let (pid, start_ticks) = (*pid, *start_ticks);
                if !is_recorded_process(pid, start_ticks) {
                    tracing::warn!(
                        pid,
                        "not killing adopted pid: it no longer names the recorded process"
                    );
                    return;
                }
                signal_pid(pid, libc::SIGKILL);
                let deadline = Instant::now() + ADOPTED_EXIT_DEADLINE;
                while !adopted_is_gone(pid, start_ticks) {
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
        let _ = self.signal_if_same(sig);
    }

    /// Signal only if the recorded process incarnation still owns its PID.
    /// The boolean lets an exact-effect caller distinguish a submitted signal
    /// from a fail-closed PID/start mismatch without weakening the existing
    /// best-effort `signal` API.
    pub(crate) fn signal_if_same(&self, sig: i32) -> Result<bool> {
        match self {
            Self::Owned(child) => {
                signal_pid_checked(child.id(), sig)?;
                Ok(true)
            }
            Self::Adopted { pid, start_ticks } => {
                if !is_recorded_process(*pid, *start_ticks) {
                    tracing::warn!(
                        pid = *pid,
                        signal = sig,
                        "not signalling adopted pid: it no longer names the recorded process"
                    );
                    return Ok(false);
                }
                signal_pid_checked(*pid, sig)?;
                Ok(true)
            }
        }
    }
}

/// Best-effort `kill(2)`. A process that has already exited answers `ESRCH`,
/// which every caller here treats as success.
fn signal_pid(pid: u32, sig: i32) {
    let _ = signal_pid_checked(pid, sig);
}

fn signal_pid_checked(pid: u32, sig: i32) -> Result<()> {
    let Some(pid) = pid_t(pid) else {
        anyhow::bail!("process id is outside the platform pid domain");
    };
    // SAFETY: `kill` copies both scalar arguments and does not retain any
    // borrowed memory.
    let result = unsafe { libc::kill(pid, sig) };
    if result == 0 {
        return Ok(());
    }
    let source = std::io::Error::last_os_error();
    if source.raw_os_error() == Some(libc::ESRCH) {
        // The exact incarnation exited between the identity sample and the
        // signal. For a stop effect, absence is already the intended result.
        return Ok(());
    }
    Err(source).with_context(|| format!("signal process {pid} with {sig}"))
}

/// Whether `pid` still names the process whose start ticks were recorded.
///
/// Off Linux, and for a record written without start ticks, both sides are
/// `None` and this is a no-op because the development path has no `/proc` to
/// sample. Anywhere the sample fails while a value was recorded, the
/// answer is "not the same process", which is the fail-closed side: the caller
/// then refuses to signal rather than risk a recycled pid.
fn is_recorded_process(pid: u32, start_ticks: Option<u64>) -> bool {
    sample_start_ticks(pid) == start_ticks
}

fn adopted_is_gone(pid: u32, start_ticks: Option<u64>) -> bool {
    !is_recorded_process(pid, start_ticks) || matches!(adopted_exited(pid), Ok(true))
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

/// Enough of a process's identity to tell it apart from a recycled pid.
///
/// A bare pid proves nothing: the kernel reuses pids, and after a restart the
/// agent has no parent/child relationship left to lean on. `start_ticks` plus
/// the executable path make the check specific to the process this node
/// actually spawned.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ProcIdentity {
    pub pid: u32,
    pub start_ticks: Option<u64>,
    pub exe: Option<PathBuf>,
}

impl ProcIdentity {
    /// Sample a live process. A process that exits mid-sample yields absent
    /// fields rather than an error: a weaker identity is a reason to refuse
    /// re-adoption later, not a reason to fail the write now.
    pub(crate) fn sample(pid: u32) -> Self {
        Self {
            pid,
            start_ticks: sample_start_ticks(pid),
            exe: sample_exe(pid),
        }
    }
}

/// Result of binding a Linux pidfd to an already-recorded process identity.
/// A pidfd is the only signal handle used by exact retirement: a numeric PID
/// can be recycled after the pre-effect inventory and must never be signalled
/// directly.
#[cfg(target_os = "linux")]
pub(crate) enum ExactPidFdOpen {
    Exact(ExactPidFd),
    Absent,
    IdentityMismatch,
    Unsupported,
}

#[cfg(target_os = "linux")]
#[derive(Debug)]
pub(crate) struct ExactPidFd {
    descriptor: OwnedFd,
}

#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PidFdSignal {
    Submitted,
    AlreadyExited,
    Unsupported,
}

#[cfg(target_os = "linux")]
impl ExactPidFd {
    /// Open the kernel handle first, then re-sample the PID's start time and
    /// executable. If the process exits and the numeric PID is recycled in
    /// that window, the pidfd still names the old task while `/proc` names the
    /// replacement; the mismatch therefore fails before any signal.
    pub(crate) fn open_exact(expected: &ProcIdentity) -> Result<ExactPidFdOpen> {
        Self::open_exact_with_sampler(expected, ProcIdentity::sample)
    }

    fn open_exact_with_sampler(
        expected: &ProcIdentity,
        sample: impl FnOnce(u32) -> ProcIdentity,
    ) -> Result<ExactPidFdOpen> {
        let Some(pid) = pid_t(expected.pid) else {
            return Ok(ExactPidFdOpen::IdentityMismatch);
        };
        if expected.start_ticks.is_none() || expected.exe.is_none() {
            return Ok(ExactPidFdOpen::IdentityMismatch);
        }
        // SAFETY: pidfd_open copies its scalar arguments and returns a fresh
        // descriptor on success. Flags are frozen to zero by the syscall ABI.
        let descriptor = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0_u32) };
        if descriptor < 0 {
            let source = std::io::Error::last_os_error();
            return match source.raw_os_error() {
                Some(libc::ESRCH) => Ok(ExactPidFdOpen::Absent),
                Some(libc::ENOSYS) | Some(libc::EINVAL) => Ok(ExactPidFdOpen::Unsupported),
                _ => Err(source).context("open exact process pidfd"),
            };
        }
        let descriptor = i32::try_from(descriptor).context("pidfd exceeds descriptor range")?;
        // SAFETY: successful pidfd_open returned one fresh descriptor, whose
        // ownership moves exactly once into OwnedFd.
        let descriptor = unsafe { OwnedFd::from_raw_fd(descriptor) };
        if sample(expected.pid) != *expected {
            return Ok(ExactPidFdOpen::IdentityMismatch);
        }
        Ok(ExactPidFdOpen::Exact(Self { descriptor }))
    }

    pub(crate) fn signal(&self, signal: i32) -> Result<PidFdSignal> {
        // SAFETY: pidfd_send_signal copies scalar arguments. A null siginfo
        // requests ordinary process-directed signal semantics and is not
        // retained by the kernel.
        let result = unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                self.descriptor.as_raw_fd(),
                signal,
                std::ptr::null::<libc::siginfo_t>(),
                0_u32,
            )
        };
        if result == 0 {
            return Ok(PidFdSignal::Submitted);
        }
        let source = std::io::Error::last_os_error();
        match source.raw_os_error() {
            Some(libc::ESRCH) => Ok(PidFdSignal::AlreadyExited),
            Some(libc::ENOSYS) | Some(libc::EINVAL) => Ok(PidFdSignal::Unsupported),
            _ => Err(source).context("signal exact process through pidfd"),
        }
    }

    /// pidfds become readable when their exact task exits. Polling this
    /// descriptor never follows a later process which reuses the numeric PID.
    pub(crate) fn exited(&self) -> Result<bool> {
        let mut descriptor = libc::pollfd {
            fd: self.descriptor.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        loop {
            // SAFETY: `descriptor` points to one initialized pollfd for this
            // nonblocking call and poll retains no pointer.
            let result = unsafe { libc::poll(&raw mut descriptor, 1, 0) };
            if result >= 0 {
                anyhow::ensure!(
                    descriptor.revents & libc::POLLNVAL == 0,
                    "exact process pidfd became invalid"
                );
                return Ok(result > 0
                    && descriptor.revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR) != 0);
            }
            let source = std::io::Error::last_os_error();
            if source.kind() != std::io::ErrorKind::Interrupted {
                return Err(source).context("poll exact process pidfd");
            }
        }
    }
}

#[cfg(target_os = "linux")]
fn sample_start_ticks(pid: u32) -> Option<u64> {
    parse_start_ticks(&std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?)
}

/// Dev and macOS hosts have no `/proc`, so V1 process identity is weaker there;
/// those paths never carry production workload.
#[cfg(not(target_os = "linux"))]
fn sample_start_ticks(_pid: u32) -> Option<u64> {
    None
}

#[cfg(target_os = "linux")]
fn sample_exe(pid: u32) -> Option<PathBuf> {
    std::fs::read_link(format!("/proc/{pid}/exe")).ok()
}

#[cfg(not(target_os = "linux"))]
fn sample_exe(_pid: u32) -> Option<PathBuf> {
    None
}

/// `starttime` — field 22 of `/proc/<pid>/stat`, in clock ticks since boot.
///
/// Field 2 (`comm`) is wrapped in parentheses and may itself contain spaces and
/// parentheses (it is the first 15 bytes of the executable's basename, which
/// the kernel does not sanitize), so the fields cannot be taken by splitting the
/// line on whitespace. Splitting after the *last* `)` is the documented way to
/// parse this file. Getting it wrong yields a plausible but wrong start time,
/// which would later let a recycled pid pass for a surviving process.
pub(crate) fn parse_start_ticks(stat: &str) -> Option<u64> {
    // Everything after the comm field starts at field 3 (`state`), so field 22
    // is at index 19.
    let (_, after_comm) = stat.rsplit_once(')')?;
    after_comm.split_whitespace().nth(19)?.parse().ok()
}

/// Identity of the current host boot. V1 adoption uses it to reject every
/// recorded pid at once after a host reboot.
pub(crate) fn host_boot_id() -> Option<String> {
    #[cfg(target_os = "linux")]
    {
        std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
            .ok()
            .map(|id| id.trim().to_string())
            .filter(|id| !id.is_empty())
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
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

    /// Adopt a live process with the start ticks sampled from the pid itself,
    /// matching the V1 runtime-adoption proof.
    fn adopt(pid: u32) -> ProcHandle {
        ProcHandle::Adopted {
            pid,
            start_ticks: sample_start_ticks(pid),
        }
    }

    /// Start ticks that provably do not belong to `pid`, on any host: off Linux
    /// nothing can be sampled, so any recorded value is already a mismatch.
    fn wrong_start_ticks(pid: u32) -> Option<u64> {
        Some(sample_start_ticks(pid).unwrap_or(0).wrapping_add(1))
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
        let deadline = Instant::now() + cats_test_support::poll_bound();
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
        let mut handle = adopt(pid);
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
        let mut adopted = adopt(adopted_child.id());
        let reaper = reap_in_background(adopted_child);
        adopted.signal(libc::SIGKILL);
        reaper.join().expect("reaper thread");
        wait_until_exited(&mut adopted);
    }

    /// An adopted process can exit long after V1 adoption and the kernel can
    /// hand its pid to something unrelated. Neither `signal` nor
    /// `kill_and_reap` may touch a pid whose start ticks have moved.
    #[test]
    fn a_recycled_adopted_pid_is_never_signalled() {
        let child = spawn_sleeper();
        let pid = child.id();
        let mut probe = adopt(pid);
        let mut stale = ProcHandle::Adopted {
            pid,
            start_ticks: wrong_start_ticks(pid),
        };

        stale.signal(libc::SIGKILL);
        assert!(
            !probe.exited().expect("probe process"),
            "signal must not reach a pid whose start ticks no longer match"
        );
        stale.kill_and_reap();
        assert!(
            !probe.exited().expect("probe process"),
            "kill_and_reap must not reach a pid whose start ticks no longer match"
        );
        // The handle itself reports the process it names as gone, because that
        // process is not what holds the pid any more.
        assert!(stale.exited().expect("probe stale handle"));

        probe.kill_and_reap();
        reap_in_background(child).join().expect("reaper thread");
    }

    #[test]
    fn start_ticks_come_from_the_field_after_the_last_paren() {
        // Real shape of /proc/<pid>/stat, truncated after starttime.
        let stat =
            "4242 (cats-blockd) S 1 4242 4242 0 -1 4194560 512 0 0 0 11 3 0 0 20 0 5 0 918273 ";
        assert_eq!(parse_start_ticks(stat), Some(918_273));

        // comm is the unsanitized executable basename, so it can contain
        // spaces and parentheses. Splitting on whitespace, or on the first
        // `)`, silently returns a different field's value here.
        let tricky =
            "4242 (odd ) name (x) S 1 4242 4242 0 -1 4194560 512 0 0 0 11 3 0 0 20 0 5 0 918273 ";
        assert_eq!(parse_start_ticks(tricky), Some(918_273));

        let trailing_paren =
            "4242 (weird)) S 1 4242 4242 0 -1 4194560 512 0 0 0 11 3 0 0 20 0 5 0 4242424 0 0";
        assert_eq!(parse_start_ticks(trailing_paren), Some(4_242_424));
    }

    #[test]
    fn a_malformed_stat_line_yields_no_start_ticks() {
        assert_eq!(parse_start_ticks(""), None);
        assert_eq!(parse_start_ticks("4242 (cats-blockd S 1 2 3"), None);
        // Truncated before field 22.
        assert_eq!(parse_start_ticks("4242 (cats-blockd) S 1 4242"), None);
        // Field 22 present but not a number.
        assert_eq!(
            parse_start_ticks(
                "4242 (cats-blockd) S 1 4242 4242 0 -1 4194560 512 0 0 0 11 3 0 0 20 0 5 0 x"
            ),
            None
        );
    }

    #[test]
    fn sampling_a_process_that_is_not_there_does_not_fail() {
        // PID 0 is never a live process, so every /proc lookup misses.
        let identity = ProcIdentity::sample(0);
        assert_eq!(identity.pid, 0);
        assert_eq!(identity.start_ticks, None);
        assert_eq!(identity.exe, None);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn pidfd_signals_and_waits_for_the_exact_kernel_task() {
        let mut child = spawn_sleeper();
        let expected = ProcIdentity::sample(child.id());
        assert!(expected.start_ticks.is_some() && expected.exe.is_some());
        let ExactPidFdOpen::Exact(pidfd) = ExactPidFd::open_exact(&expected).unwrap() else {
            panic!("positive calibration: this Linux kernel must open an exact pidfd")
        };
        assert!(!pidfd.exited().unwrap());
        assert_eq!(pidfd.signal(libc::SIGKILL).unwrap(), PidFdSignal::Submitted);
        let deadline = Instant::now() + cats_test_support::poll_bound();
        while !pidfd.exited().unwrap() {
            assert!(
                Instant::now() < deadline,
                "pidfd never reported process exit"
            );
            std::thread::sleep(ADOPTED_EXIT_POLL);
        }
        assert!(!child.wait().unwrap().success());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn pidfd_open_barrier_rejects_a_replacement_sample_without_signalling() {
        let mut child = spawn_sleeper();
        let expected = ProcIdentity::sample(child.id());
        assert!(matches!(
            ExactPidFd::open_exact(&expected).unwrap(),
            ExactPidFdOpen::Exact(_)
        ));
        let mut replacement = expected.clone();
        replacement.start_ticks = replacement.start_ticks.map(|ticks| ticks + 1);
        assert!(matches!(
            ExactPidFd::open_exact_with_sampler(&expected, |_| replacement).unwrap(),
            ExactPidFdOpen::IdentityMismatch
        ));
        assert!(
            child.try_wait().unwrap().is_none(),
            "the replacement barrier must return before any signal reaches the PID"
        );
        child.kill().unwrap();
        assert!(!child.wait().unwrap().success());
    }

    #[test]
    fn host_boot_id_is_stable_within_one_boot() {
        // None off Linux by design; on Linux the value must not vary between
        // reads, or step 1 of the re-adoption check would reject everything.
        assert_eq!(host_boot_id(), host_boot_id());
        #[cfg(target_os = "linux")]
        assert!(host_boot_id().is_some_and(|id| !id.trim().is_empty()));
        #[cfg(not(target_os = "linux"))]
        assert_eq!(host_boot_id(), None);
    }
}
