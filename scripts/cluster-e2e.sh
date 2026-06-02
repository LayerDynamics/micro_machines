#!/usr/bin/env bash
# End-to-end cluster boot (SPEC-1 FR-17/FR-18/FR-19, NFR-R2): stand up a real
# control plane + a real host agent over mutual-TLS, then boot a microVM through the
# cluster and prove it survives a controller restart.
#
# Flow: mm-controller (REST + gRPC + reconcile) + mm-agent (boots VMs via mm-host)
# over mTLS, backed by Postgres. `mm --server run --ssh` creates a machine; the
# scheduler places it on the agent; the agent boots a real microVM (sandbox mode, so
# it stays up) and reports Running + its IP; we assert `mm ps` shows it Running with
# a 10.0.0.x IP, restart the controller, and assert it is still Running.
#
# Requires (the CI cluster-integration job provides all): /dev/kvm, root, Postgres
# via DATABASE_URL, openssl + bash, and the kernel/mm-init/dropbear fixtures pointed
# at by MM_KERNEL/MM_INIT/MM_SSHD. Run as root.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SECRET="cluster-e2e-secret"
NS="e2e"
REST="http://127.0.0.1:8080"
GRPC="https://127.0.0.1:50051"

CONTROLLER_BIN="${CONTROLLER_BIN:-$ROOT/target/debug/mm-controller}"
AGENT_BIN="${AGENT_BIN:-$ROOT/target/debug/mm-agent}"
MM_BIN="${MM_BIN:-$ROOT/target/debug/mm}"

WORK="$(mktemp -d)"
# mktemp creates 0700; the jailed worker drops to uid 65534 and must traverse the
# whole path down to its chroot, so make the state tree world-traversable.
chmod 0755 "$WORK"
CERTS="$WORK/certs"
STATE="$WORK/state"
mkdir -p "$STATE"
chmod 0755 "$STATE"

# Dev mTLS certs (server SAN includes IP:127.0.0.1, which the agent dials).
CONTROLLER_DNS=localhost bash "$ROOT/scripts/dev-certs.sh" "$CERTS"

# Mint an HS256 JWT the controller's verifier accepts (sub=admin).
b64url() { openssl base64 -A | tr '+/' '-_' | tr -d '='; }
mint_token() {
  local header payload exp h p sig
  header='{"alg":"HS256","typ":"JWT"}'
  exp=$(( $(date +%s) + 3600 ))
  payload="{\"sub\":\"admin\",\"iss\":\"e2e\",\"aud\":\"mm\",\"exp\":$exp}"
  h=$(printf '%s' "$header" | b64url)
  p=$(printf '%s' "$payload" | b64url)
  sig=$(printf '%s' "$h.$p" | openssl dgst -binary -sha256 -hmac "$SECRET" | b64url)
  printf '%s.%s.%s' "$h" "$p" "$sig"
}
TOKEN="$(mint_token)"

CTRL_PID=""
AGENT_PID=""
cleanup() {
  "$MM_BIN" --server "$REST" --token "$TOKEN" --namespace "$NS" rm c1 >/dev/null 2>&1 || true
  [ -n "$AGENT_PID" ] && kill "$AGENT_PID" 2>/dev/null || true
  [ -n "$CTRL_PID" ] && kill "$CTRL_PID" 2>/dev/null || true
}
trap cleanup EXIT

mm() { "$MM_BIN" --server "$REST" --token "$TOKEN" --namespace "$NS" "$@"; }

start_controller() {
  "$CONTROLLER_BIN" \
    --database-url "$DATABASE_URL" \
    --listen 127.0.0.1:8080 \
    --grpc-listen 127.0.0.1:50051 \
    --jwt-hs256-secret "$SECRET" \
    --tls-dir "$CERTS" \
    --reconcile-interval-secs 2 &
  CTRL_PID=$!
}

wait_rest() {
  for _ in $(seq 1 60); do
    curl -fsS "$REST/healthz" >/dev/null 2>&1 && return 0
    sleep 1
  done
  echo "FAIL: controller REST never came up" >&2
  exit 1
}

# --- 1. controller up ------------------------------------------------------
start_controller
wait_rest
echo "controller up"

# --- 2. real agent up (boots VMs) ------------------------------------------
"$AGENT_BIN" run \
  --controller "$GRPC" \
  --host-id host-1 \
  --state-root "$STATE" \
  --tls-dir "$CERTS" \
  --kernel "$MM_KERNEL" \
  --init "$MM_INIT" \
  ${MM_SSHD:+--sshd "$MM_SSHD"} \
  --vcpus-total 4 --mem-mib-total 4096 &
AGENT_PID=$!
sleep 4   # let the agent register capacity
echo "agent up"

# --- 3. boot a microVM through the cluster ---------------------------------
# --ssh => sandbox mode, so the guest stays up (reap_forever) rather than powering
# off when a workload exits — letting us observe Running + restart survival.
mm run --ssh --name c1 docker.io/library/busybox:latest
echo "requested c1; waiting for it to boot on the agent..."

booted=0
for _ in $(seq 1 90); do
  out="$(mm ps || true)"
  if echo "$out" | grep -Eq "c1 +running +10\.0\.0\."; then
    booted=1
    echo "$out"
    break
  fi
  sleep 2
done
if [ "$booted" != 1 ]; then
  echo "FAIL: c1 did not reach Running with an IP" >&2
  mm ps || true
  cat "$STATE"/jails/*/console.log 2>/dev/null || true
  exit 1
fi
echo "PASS: c1 booted on the agent via the cluster"

# --- 3.5 cluster exec: controller -> agent -> guest (FR-13) ----------------
# Run here, right after boot: a successful boot proves the agent is connected and
# processing its streams, so there is no reconnection race (the post-restart survival
# of the reverse channel is checked separately in step 4.5, with a retry).
echo "testing cluster exec (controller -> agent -> guest)..."
out="$(mm exec c1 echo hello-from-guest)"
echo "exec stdout: [$out]"
if ! echo "$out" | grep -q "hello-from-guest"; then
  echo "FAIL: cluster exec did not return the guest command's stdout" >&2
  cat "$STATE"/jails/*/console.log 2>/dev/null || true
  exit 1
fi
echo "PASS: cluster exec returned the guest's stdout"

# A non-zero guest exit code must propagate all the way back to the client.
set +e
mm exec c1 sh -c 'exit 7' >/dev/null 2>&1
rc=$?
set -e
if [ "$rc" != 7 ]; then
  echo "FAIL: cluster exec did not propagate exit code 7 (got $rc)" >&2
  exit 1
fi
echo "PASS: cluster exec propagated the guest's non-zero exit code"

# An exec against an unknown machine must fail fast (not hang) with a non-zero exit.
set +e
mm exec no-such-machine true >/dev/null 2>&1
rc=$?
set -e
if [ "$rc" = 0 ]; then
  echo "FAIL: cluster exec against a missing machine unexpectedly succeeded" >&2
  exit 1
fi
echo "PASS: cluster exec against a missing machine failed fast (rc=$rc)"

# --- 4. restart the controller; the running VM must survive (NFR-R2) -------
kill "$CTRL_PID"; wait "$CTRL_PID" 2>/dev/null || true
CTRL_PID=""
echo "controller killed; restarting..."
start_controller
wait_rest
sleep 4   # let the agent reconnect + a reconcile tick run
out="$(mm ps || true)"
echo "$out"
if echo "$out" | grep -Eq "c1 +running"; then
  echo "PASS: c1 still Running after controller restart (NFR-R2)"
else
  echo "FAIL: c1 not Running after controller restart" >&2
  exit 1
fi

# --- 4.5 cluster exec survives the controller restart ----------------------
# The agent re-opens its WatchExec stream against the restarted controller on
# reconnect (~5s). Retry until the reverse channel is back rather than racing that
# sleep — proving the exec path re-establishes, not just the VM.
exec_ok=0
for _ in $(seq 1 30); do
  if out="$(mm exec c1 echo exec-after-restart 2>/dev/null)" \
     && echo "$out" | grep -q "exec-after-restart"; then
    exec_ok=1
    break
  fi
  sleep 2
done
if [ "$exec_ok" != 1 ]; then
  echo "FAIL: cluster exec did not recover after the controller restart" >&2
  exit 1
fi
echo "PASS: cluster exec reverse channel survived the controller restart"

# --- 5. remove it ----------------------------------------------------------
mm rm c1
echo "CLUSTER E2E OK"
