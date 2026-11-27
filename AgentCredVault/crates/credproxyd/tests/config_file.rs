//! Bootstrap config file: file values reach the daemon, the command line wins
//! over the file, and a malformed or missing explicit file fails before the
//! daemon binds anything.

use std::path::{Path, PathBuf};
use std::time::Duration;

mod support;
use support::*;

fn write_config(dir: &Path, body: &str) -> PathBuf {
    let path = dir.join("credproxyd.json");
    std::fs::write(&path, body).unwrap();
    path
}

#[tokio::test(flavor = "multi_thread")]
async fn bootstrap_config_file() {
    let store = start_store("credproxyd-config-file").await;
    let dir = scratch("credproxy-config-file-ctl");
    let state = dir.path().join("state").join("daemon.json");
    // The listener is a bootstrap input; an ephemeral port keeps the case
    // independent of a deployed instance holding 4100.
    let listen = format!("127.0.0.1:{}", free_port());

    // 1. Both socket paths and the listener come from the file. Nothing else
    //    is set: the programs read no environment variable.
    let mgmt1 = dir.path().join("from-file.sock");
    let file1 = write_config(
        dir.path(),
        &format!(
            r#"{{"store_socket":"{}","mgmt_socket":"{}","store_wait_ms":2000,"listen_transparent":"{listen}"}}"#,
            store.sock.display(),
            mgmt1.display()
        ),
    );
    let d1 = spawn_daemon(&[
        "--config",
        file1.to_str().unwrap(),
        "--state-file",
        state.to_str().unwrap(),
    ]);
    assert!(
        wait_for_path(&mgmt1, Duration::from_secs(10)).await,
        "management socket from the config file did not appear"
    );
    sigterm(&d1);
    let out = wait_output(d1, Duration::from_secs(5)).await;
    assert!(out.status.success(), "clean shutdown on SIGTERM");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains(&format!("bootstrap config {}", file1.display())),
        "startup names the config file in effect: {stderr}"
    );

    // 2. The command line wins over the file for the same field. The file's
    //    management socket path is never created.
    let mgmt_file = dir.path().join("file-loses.sock");
    let mgmt_arg = dir.path().join("arg-wins.sock");
    let file2 = write_config(
        dir.path(),
        &format!(
            r#"{{"store_socket":"{}","mgmt_socket":"{}","store_wait_ms":2000,"listen_transparent":"{listen}"}}"#,
            store.sock.display(),
            mgmt_file.display()
        ),
    );
    let d2 = spawn_daemon(&[
        "--config",
        file2.to_str().unwrap(),
        "--mgmt-socket",
        mgmt_arg.to_str().unwrap(),
        "--state-file",
        state.to_str().unwrap(),
    ]);
    assert!(
        wait_for_path(&mgmt_arg, Duration::from_secs(10)).await,
        "command-line management socket did not appear"
    );
    assert!(
        !mgmt_file.exists(),
        "the file's management socket must not be created when the argument wins"
    );
    sigterm(&d2);
    let out = wait_output(d2, Duration::from_secs(5)).await;
    assert!(out.status.success(), "clean shutdown on SIGTERM");

    // 3. Keys that belong to the daemon's own configuration are hard errors,
    //    not silently ignored second sources of truth; a listener that is not
    //    an `ip:port` is rejected before anything binds.
    for bad_body in [
        format!(
            r#"{{"store_socket":"{}","server":{{"listen_transparent":"{listen}"}}}}"#,
            store.sock.display()
        ),
        format!(
            r#"{{"store_socket":"{}","listen_transparent":"not-an-address"}}"#,
            store.sock.display()
        ),
    ] {
        let bad = write_config(dir.path(), &bad_body);
        let mgmt3 = dir.path().join("never.sock");
        let d3 = spawn_daemon(&[
            "--config",
            bad.to_str().unwrap(),
            "--mgmt-socket",
            mgmt3.to_str().unwrap(),
            "--state-file",
            state.to_str().unwrap(),
        ]);
        let out = wait_output(d3, Duration::from_secs(10)).await;
        assert!(
            !out.status.success(),
            "bad key must refuse startup: {bad_body}"
        );
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            stderr.contains("parse config file") || stderr.contains("expected ip:port"),
            "{stderr}"
        );
        assert!(
            !mgmt3.exists(),
            "no management socket after a rejected file"
        );
    }

    // 4. An explicitly named file that does not exist is fatal.
    let missing = dir.path().join("absent.json");
    let mgmt4 = dir.path().join("never4.sock");
    let d4 = spawn_daemon(&[
        "--config",
        missing.to_str().unwrap(),
        "--mgmt-socket",
        mgmt4.to_str().unwrap(),
        "--state-file",
        state.to_str().unwrap(),
    ]);
    let out = wait_output(d4, Duration::from_secs(10)).await;
    assert!(
        !out.status.success(),
        "missing explicit file must refuse startup"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("read config file"), "{stderr}");
    assert!(!mgmt4.exists(), "no management socket after a missing file");

    // 5. `upstream_ca` is consumed, not merely accepted: it has no
    //    command-line form, so a path in the file is the only channel, and an
    //    unreadable one refuses startup instead of silently verifying against
    //    the standard roots alone.
    let ca_file = write_config(
        dir.path(),
        &format!(
            r#"{{"store_socket":"{}","mgmt_socket":"{}","store_wait_ms":2000,"listen_transparent":"{listen}","upstream_ca":"/nonexistent/ca.pem"}}"#,
            store.sock.display(),
            dir.path().join("ca-case.sock").display()
        ),
    );
    let d5 = spawn_daemon(&[
        "--config",
        ca_file.to_str().unwrap(),
        "--state-file",
        state.to_str().unwrap(),
    ]);
    let out = wait_output(d5, Duration::from_secs(10)).await;
    assert!(
        !out.status.success(),
        "unreadable upstream_ca must refuse startup"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("read test CA"), "{stderr}");

    // 6. The capture section is validated before netfilter is touched: an
    //    invalid subnet refuses startup even though iptables was never run.
    let mgmt6 = dir.path().join("capture.sock");
    let capture = write_config(
        dir.path(),
        &format!(
            r#"{{"store_socket":"{}","mgmt_socket":"{}","capture":{{"interface":"virbr0","subnet":"192.168.56.1/24","gateway":"192.168.56.1"}}}}"#,
            store.sock.display(),
            mgmt6.display()
        ),
    );
    let d6 = spawn_daemon(&[
        "--config",
        capture.to_str().unwrap(),
        "--state-file",
        state.to_str().unwrap(),
    ]);
    let out = wait_output(d6, Duration::from_secs(10)).await;
    assert!(
        !out.status.success(),
        "invalid capture config must refuse startup"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("capture configuration"), "{stderr}");
    assert!(
        !mgmt6.exists(),
        "no management socket after a rejected capture config"
    );
}
