//! Inter-host milestone IH5, from `vvagent`'s side of the `vvssh` lane.
//!
//! `vvssh` runs `vvagent bridge --dial <destination> --stdin-leash --parent-pid <vvssh> -- ssh …
//! <remote command>` and decides from the exit status whether to try again. These tests run that
//! exact shape, with a fake `ssh` that executes the remote command locally, so the POSIX remote
//! command, the leash, and every exit status are exercised without an SSH server.
#![cfg(unix)]

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::Value;

const BIN: &str = env!("CARGO_BIN_EXE_vvagent");

/// What `vvssh`'s lane asks a POSIX host to run (`vivido/src/bin/vvssh/mesh.rs`), verbatim.
const REMOTE_COMMAND: &str = "command -v vvagent >/dev/null 2>&1 && exec vvagent bridge --serve; \
     exec \"${SHELL:-/bin/sh}\" -lc 'exec vvagent bridge --serve'";

struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str) -> Self {
        let base = std::env::temp_dir().join(format!(
            "vvagent-ih5-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(base.join("remote-bin")).unwrap();
        std::fs::create_dir_all(base.join("empty-bin")).unwrap();
        let scratch = Self(base);
        scratch.script(
            "ssh",
            // Drop every argument but the last, which is the remote command, and run it the way
            // sshd would: through a shell.
            "#!/bin/sh\nfor last; do :; done\nexec /bin/sh -c \"$last\"\n",
        );
        scratch
    }

    fn db(&self, host: &str) -> PathBuf {
        self.0.join(host).join("mesh.sqlite")
    }

    fn script(&self, name: &str, body: &str) -> PathBuf {
        let path = self.0.join(name);
        std::fs::write(&path, body).unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        path
    }

    /// Put a `vvagent` on the "remote" PATH that serves from `host`'s store.
    fn install_remote(&self, host: &str) -> PathBuf {
        let bin = self.0.join("remote-bin");
        let wrapper = bin.join("vvagent");
        std::fs::write(
            &wrapper,
            format!(
                "#!/bin/sh\nexec '{BIN}' --db '{}' \"$@\"\n",
                self.db(host).display()
            ),
        )
        .unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&wrapper, std::fs::Permissions::from_mode(0o700)).unwrap();
        bin
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn clean(command: &mut Command) -> &mut Command {
    for key in [
        "AGENT_MESH_ENDPOINT",
        "AGENT_MESH_TOKEN_FILE",
        "AGENT_MESH_RUNTIME",
        "AGENT_MESH_INSTANCE",
        "AGENT_MESH_ADDRESS",
    ] {
        command.env_remove(key);
    }
    command
}

/// The lane's command, dialling `destination` with the remote `PATH` set to `remote_path`.
fn lane(scratch: &Scratch, destination: &str, remote_path: &Path) -> Command {
    let mut command = Command::new(BIN);
    clean(&mut command)
        .arg("--db")
        .arg(scratch.db("laptop"))
        .args([
            "bridge",
            "--dial",
            destination,
            "--stdin-leash",
            "--parent-pid",
        ])
        .arg(std::process::id().to_string())
        .arg("--")
        .arg(scratch.0.join("ssh"))
        .args(["-T", "-o", "ControlMaster=no", "-o", "ControlPath=none"])
        .arg(destination)
        .arg(REMOTE_COMMAND)
        // The remote side's environment: its PATH, and a login shell that adds nothing.
        .env("PATH", format!("{}:/usr/bin:/bin", remote_path.display()))
        .env("SHELL", "/bin/sh")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    command
}

fn peers(db: &Path) -> Vec<Value> {
    let output = clean(&mut Command::new(BIN))
        .arg("--db")
        .arg(db)
        .args(["peer", "list"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    value["peers"].as_array().cloned().unwrap_or_default()
}

fn connected(db: &Path) -> bool {
    peers(db)
        .first()
        .is_some_and(|peer| peer["connected"] == true)
}

fn until(what: &str, mut ready: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(20);
    while !ready() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn wait_exit(child: &mut Child) -> (i32, Value) {
    let deadline = Instant::now() + Duration::from_secs(20);
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        assert!(Instant::now() < deadline, "the bridge did not exit");
        std::thread::sleep(Duration::from_millis(20));
    };
    let mut stderr = String::new();
    child
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut stderr)
        .unwrap();
    let error = stderr
        .lines()
        .rev()
        .find_map(|line| serde_json::from_str::<Value>(line).ok())
        .unwrap_or(Value::Null);
    (status.code().unwrap_or(-1), error)
}

#[test]
fn the_lane_bridges_over_ssh_and_leaves_both_leases_free_when_its_stdin_closes() {
    let scratch = Scratch::new("leash");
    let remote = scratch.install_remote("buildbox");
    let mut bridge = lane(&scratch, "wensheng@BuildBox", &remote)
        .spawn()
        .unwrap();

    until("the lane to connect", || connected(&scratch.db("laptop")));
    until("buildbox to see it", || connected(&scratch.db("buildbox")));
    assert_eq!(
        peers(&scratch.db("laptop"))[0]["label"],
        "buildbox",
        "an SSH destination names the peer by its host"
    );

    // What `vvssh` does when its session ends.
    drop(bridge.stdin.take());
    let (code, _) = wait_exit(&mut bridge);
    assert_eq!(code, 0, "a clean close");
    assert!(
        !connected(&scratch.db("laptop")),
        "this side's lease is free at once"
    );
    until("the far side's lease to be free too", || {
        !connected(&scratch.db("buildbox"))
    });

    // So an immediate reconnect is served, rather than stood aside from.
    let mut again = lane(&scratch, "wensheng@BuildBox", &remote)
        .spawn()
        .unwrap();
    until("the reconnect", || connected(&scratch.db("buildbox")));
    drop(again.stdin.take());
    assert_eq!(wait_exit(&mut again).0, 0);
}

#[test]
fn every_way_a_lane_can_end_says_whether_trying_again_can_help() {
    let scratch = Scratch::new("endings");
    let remote = scratch.install_remote("buildbox");

    // No vvagent anywhere on the far side, not even through a login shell: unreachable.
    let mut missing = lane(&scratch, "buildbox", &scratch.0.join("empty-bin"))
        .spawn()
        .unwrap();
    let (code, error) = wait_exit(&mut missing);
    assert_eq!(code, 69, "{error}");
    assert_eq!(error["error"]["code"], "peer_unreachable");

    // Another window already serves this peer: stand aside.
    let mut first = lane(&scratch, "buildbox", &remote).spawn().unwrap();
    until("the first lane", || connected(&scratch.db("laptop")));
    let mut second = lane(&scratch, "buildbox", &remote).spawn().unwrap();
    assert_eq!(wait_exit(&mut second).0, 75);
    drop(first.stdin.take());
    assert_eq!(wait_exit(&mut first).0, 0);

    // The label now answers from a different store: refused, and not worth retrying.
    let elsewhere = scratch.install_remote("impostor");
    let mut refused = lane(&scratch, "buildbox", &elsewhere).spawn().unwrap();
    let (code, error) = wait_exit(&mut refused);
    assert_eq!(code, 1, "{error}");
    assert_eq!(error["error"]["code"], "peer_mismatch");
}

#[test]
fn peer_connect_does_what_the_lane_does_from_a_plain_terminal() {
    let scratch = Scratch::new("connect");
    let remote = scratch.install_remote("buildbox");
    let mut connect = clean(&mut Command::new(BIN))
        .arg("--db")
        .arg(scratch.db("laptop"))
        .args(["peer", "connect", "user@buildbox", "--", "-p", "2222"])
        .env("AGENT_MESH_SSH", scratch.0.join("ssh"))
        .env("PATH", format!("{}:/usr/bin:/bin", remote.display()))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    until("the foreground bridge to connect", || {
        connected(&scratch.db("laptop"))
    });
    assert_eq!(peers(&scratch.db("laptop"))[0]["label"], "buildbox");
    let _ = connect.kill();
    let _ = connect.wait();
}
