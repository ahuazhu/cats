use super::*;

impl NodeRuntime {
    pub(super) fn write_disk_map(&self, rt: &CatRuntime) -> Result<()> {
        let map: HashMap<String, DiskMapEntry> = rt
            .blockds
            .iter()
            .map(|(disk_id, p)| {
                (
                    disk_id.clone(),
                    DiskMapEntry {
                        socket: p.socket.clone(),
                        mount_path: p.grant.mount_path.clone(),
                    },
                )
            })
            .collect();
        let tmp = rt.disk_map_path().with_extension("tmp");
        std::fs::write(&tmp, serde_json::to_vec(&map)?)?;
        std::fs::rename(&tmp, rt.disk_map_path())?;
        Ok(())
    }

    pub(super) fn spawn_guest(&self, rt: &CatRuntime, state_file: Option<&Path>) -> Result<Child> {
        let mut cmd = Command::new(&self.cfg.guest_agent_bin);
        cmd.arg("--control-socket")
            .arg(rt.ctl_socket())
            .arg("--disk-map")
            .arg(rt.disk_map_path())
            .arg("--web-socket")
            .arg(rt.web_socket())
            // FakeVmm runs the Guest Agent as a host process, so the Node
            // supplies an isolated test socket. A real VMM never opens the
            // Guest's /run/cats/runtime.sock.
            .arg("--runtime-socket")
            .arg(rt.runtime_socket())
            .stdout(Stdio::null())
            .stderr(std::fs::File::create(rt.dir.join("guest.log")).context("create guest log")?);
        if let Some(sf) = state_file {
            cmd.arg("--state-file").arg(sf);
        }
        cmd.spawn().context("spawn cats-guest-agent")
    }

    pub(super) fn wait_guest_ready(&self, rt: &CatRuntime) -> Result<String> {
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            if let Ok(mut client) = rt.conn().connect() {
                if let Ok((boot_id, _)) = client.health() {
                    return Ok(boot_id);
                }
            }
            if Instant::now() > deadline {
                bail!("guest agent never became healthy");
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }
}

pub(super) fn signal(child: &Child, sig: i32) {
    if let Ok(pid) = i32::try_from(child.id()) {
        // SAFETY: `pid` comes from the live `Child`; `kill` copies both scalar
        // arguments and does not retain any borrowed memory.
        unsafe {
            libc::kill(pid, sig);
        }
    }
}
