//! Cluster exec on the agent side (SPEC-1 FR-13).
//!
//! The agent dials the controller's `WatchExec` server-stream (the reverse channel
//! into this client-only process); for each pushed [`ExecTask`] it resolves the local
//! machine's vsock bridge socket, runs the command via the streaming exec client, and
//! forwards each output chunk back to the controller over a `ReportExecResult`
//! client-stream. Output is *streamed*, not buffered, so a long-running command's
//! stdout reaches the originating `mm exec` caller as it is produced.
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result};
use mm_proto::machine_service_client::MachineServiceClient;
use mm_proto::{ExecChunk, ExecTask};
use mm_sandbox::exec::{connect_exec_ready, run_exec_streaming, ExecEvent, EXEC_PORT};
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::transport::Channel;

use crate::actuator::HostConfig;
use crate::local_store::LocalStore;

/// The in-guest exec request id. Each exec uses a fresh vsock connection, so a single
/// id per connection suffices (matches the single-host `mm exec`).
const GUEST_EXEC_ID: u64 = 1;
/// How long to retry connecting to the guest exec agent. A machine can report
/// `Running` (and so be a valid exec target) moments before its in-guest exec agent
/// is listening, so we ride out that startup window rather than fail the first try.
/// Kept under the controller's REST wait (command timeout + grace) so the two ends
/// cannot desync.
const EXEC_CONNECT_TIMEOUT: Duration = Duration::from_secs(20);

/// The resolved target of an exec task: either a ready guest bridge + command, or a
/// reason the command cannot run (reported to the caller as a terminal error chunk).
enum Target {
    Ready {
        vsock_path: PathBuf,
        cmd: Vec<String>,
        timeout_ms: u64,
    },
    Error(String),
}

/// Handle one pushed exec task end-to-end: resolve the target guest, run the command,
/// and stream the result back to the controller. Resolution/transport failures are
/// reported to the caller as a terminal error chunk rather than dropped, so a
/// `mm exec` never hangs waiting for output that will not come.
pub async fn run_and_report(
    machines: &mut MachineServiceClient<Channel>,
    store: &LocalStore,
    host: &HostConfig,
    task: ExecTask,
) -> Result<()> {
    let request_id = task.request_id.clone();
    let target = resolve_target(store, host, &task);
    let (tx, rx) = mpsc::channel::<ExecChunk>(64);

    // Producer: run the (blocking) streaming exec on a blocking thread, pushing each
    // event up as an ExecChunk as the guest produces it.
    let producer = tokio::task::spawn_blocking(move || produce_chunks(target, &request_id, tx));

    // Consumer: stream those chunks to the controller. Driving this concurrently with
    // the producer is what makes output flow as it is generated rather than in a batch.
    machines
        .report_exec_result(ReceiverStream::new(rx))
        .await
        .context("reporting exec result to controller")?;
    // Join the producer; its expected errors are already delivered as chunks, so this
    // only surfaces an actual panic in the blocking task.
    producer.await.context("exec producer task panicked")?;
    Ok(())
}

/// Resolve which guest the task targets and where its host vsock bridge socket lives,
/// mirroring the single-host `mm exec` checks (machine exists on this host + running).
fn resolve_target(store: &LocalStore, host: &HostConfig, task: &ExecTask) -> Target {
    let request = match &task.request {
        Some(r) => r,
        None => return Target::Error("exec task carried no request".into()),
    };
    let uid = match &request.r#ref {
        Some(r) => r.uid.as_str(),
        None => return Target::Error("exec request carried no machine ref".into()),
    };
    // The task carries only the controller's uid; the host-local jail dir is named
    // after the record this agent persisted at boot, so look it up rather than
    // reconstruct it.
    let record = match store.get(uid) {
        Ok(Some(m)) => m,
        Ok(None) => return Target::Error(format!("no machine {uid} on this host")),
        Err(e) => return Target::Error(format!("reading local store: {e}")),
    };
    if record.pid.is_none() {
        return Target::Error(format!("machine {} is not running", record.name));
    }
    let vsock_path = host
        .state_root
        .join("jails")
        .join(&record.name)
        .join("vsock.sock");
    if !vsock_path.exists() {
        return Target::Error(format!(
            "machine {} has no vsock bridge socket at {}",
            record.name,
            vsock_path.display()
        ));
    }
    Target::Ready {
        vsock_path,
        cmd: request.cmd.clone(),
        timeout_ms: request.timeout_ms,
    }
}

/// Drive the blocking exec and push each event to `tx` as an [`ExecChunk`]. Always
/// delivers a terminal frame (an exit chunk from the guest, or an error chunk on a
/// resolution/transport failure) so the controller can release the waiting caller.
fn produce_chunks(target: Target, request_id: &str, tx: mpsc::Sender<ExecChunk>) {
    let (vsock_path, cmd, timeout_ms) = match target {
        Target::Ready {
            vsock_path,
            cmd,
            timeout_ms,
        } => (vsock_path, cmd, timeout_ms),
        Target::Error(msg) => {
            let _ = tx.blocking_send(terminal_error(request_id, &msg));
            return;
        }
    };

    // Retry the connect+handshake: the guest exec agent may not be listening the
    // instant the machine reports Running. A bounded retry rides out that window
    // instead of failing (or, before the handshake had a read timeout, hanging).
    let mut stream = match connect_exec_ready(&vsock_path, EXEC_PORT, EXEC_CONNECT_TIMEOUT) {
        Ok(s) => s,
        Err(e) => {
            let _ = tx.blocking_send(terminal_error(
                request_id,
                &format!("connecting to guest exec agent: {e}"),
            ));
            return;
        }
    };

    let mut sent_terminal = false;
    let run = run_exec_streaming(&mut stream, GUEST_EXEC_ID, &cmd, timeout_ms, |event| {
        let chunk = match event {
            ExecEvent::Stdout(data) => output_chunk(request_id, "stdout", data),
            ExecEvent::Stderr(data) => output_chunk(request_id, "stderr", data),
            ExecEvent::Exit(code) => {
                sent_terminal = true;
                exit_chunk(request_id, code)
            }
        };
        tx.blocking_send(chunk).map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::BrokenPipe, "controller stream closed")
        })
    });
    // A transport error before the guest's Exit frame: still give the caller a
    // terminal frame (unless the failure was the caller hanging up, in which case the
    // send would fail anyway and is harmless).
    if run.is_err() && !sent_terminal {
        let _ = tx.blocking_send(terminal_error(
            request_id,
            "exec stream closed before the guest reported an exit code",
        ));
    }
}

/// An output chunk on `stream` ("stdout"/"stderr"), tagged with the request id.
fn output_chunk(request_id: &str, stream: &str, data: Vec<u8>) -> ExecChunk {
    ExecChunk {
        stream: stream.to_string(),
        data,
        exit_code: 0,
        done: false,
        request_id: request_id.to_string(),
        error: String::new(),
    }
}

/// The terminal frame carrying the guest command's exit code.
fn exit_chunk(request_id: &str, code: i32) -> ExecChunk {
    ExecChunk {
        stream: String::new(),
        data: Vec::new(),
        exit_code: code,
        done: true,
        request_id: request_id.to_string(),
        error: String::new(),
    }
}

/// A terminal error frame: a transport/resolution failure (distinct from a command
/// that ran and exited non-zero), with exit code -1.
fn terminal_error(request_id: &str, msg: &str) -> ExecChunk {
    ExecChunk {
        stream: String::new(),
        data: Vec::new(),
        exit_code: -1,
        done: true,
        request_id: request_id.to_string(),
        error: msg.to_string(),
    }
}
