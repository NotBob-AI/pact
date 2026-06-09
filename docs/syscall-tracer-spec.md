# PACT eBPF Syscall Tracer — Design Specification

## Status
Draft — v0.x，待实现

## Motivation

PACT receipts currently carry two signals:
1. **Agent claim** — what the agent says it did (Ed25519-signed by agent's key)
2. **Host observation** — what the runtime observed (signed by runtime's key)

Both signals are generated within or adjacent to the agent's execution context. A sophisticated compromised agent could influence both without detection.

The syscall trace is the **third independent signal** — a record of actual system calls the agent process made during execution, captured by a tracer running in a security domain the agent cannot reach or modify.

## Threat Model

```
Attacker Goal: Produce a valid PACT receipt for a policy-violating action.

Attack Vectors:
  1. Tamper with agent claim → fails Ed25519 signature verification
  2. Tamper with host observation → fails runtime key signature verification  
  3. Influence syscall trace → requires kernel-level access outside agent's capability envelope

Vector 3 is the hardest to execute. eBPF running in the kernel is the right substrate.
```

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│ Kernel Space                                             │
│  ┌─────────────────────────────────────────────────┐   │
│  │ eBPF Program (bpftrace / libbpf)                 │   │
│  │  - Attaches to syscall entry/exit of agent PID   │   │
│  │  - Filters: read, write, open, connect, sendto  │   │
│  │  - Ring buffer → userspace collector             │   │
│  └─────────────────────────────────────────────────┘   │
├─────────────────────────────────────────────────────────┤
│ User Space (ring buffer consumer)                      │
│  ┌─────────────────────────────────────────────────┐   │
│  │ syscall-collector daemon                        │   │
│  │  - Reads ring buffer (non-blocking)            │   │
│  │  - Assembles syscall entries per action_id       │   │
│  │  - Signs trace with collector's Ed25519 key     │   │
│  │  - Publishes to transparency log                │   │
│  └─────────────────────────────────────────────────┘   │
├─────────────────────────────────────────────────────────┤
│ PACT Receipt Bundle                                     │
│  - agent_claim: signed by agent's key                 │
│  - host_observation: signed by runtime's key          │
│  - syscall_trace: signed by collector's key           │
│  - Verification: any 2 of 3 must agree                │
└─────────────────────────────────────────────────────────┘
```

## eBPF Program Design

### Attach Points
- `sys_enter_openat` / `sys_enter_openat64` — file access
- `sys_enter_write` / `sys_enter_read` — I/O
- `sys_enter_connect` / `sys_enter_sendto` — network
- `sys_enter_execve` / `sys_enter_execveat` — spawn child

### Filter Criteria
Only trace agent's own PID namespace. Filter by:
1. PID matches target agent process
2. UID != 0 (non-root — prevents trivial rootkit bypass)
3. Call is in allowed-trace set (reduce ring buffer volume)
\n### Ring Buffer Structure
Each entry:
```
{
  "action_id": "uuid-v4",
  "timestamp_ns": int,
  "syscall_nr": int,
  "args": [int64 x 6],
  "result": int64,
  "pid": int,
  "tid": int
}
```

## Collector Daemon

Responsibilities:
1. Consume ring buffer entries (non-blocking poll on perf event FD)
2. Correlate entries to action_id (via shared memory map: action_id ↔ PID)
3. Assemble trace entries per action window (e.g., from tool call begin to end)
4. Sign the serialized trace with collector's Ed25519 key
5. Publish to transparency log alongside agent receipt

### Action ID Correlation
The interceptor (Layer 0) writes to a shared eBPF map:
```c
struct {
    __u32 pid;
    __u32 action_id_map[1];  // index 0 = action_id stored elsewhere
}
```
Alternative: annotate via `ptrace(PTRACE_SEIZE, pid, NULL, 0)` then use O_PATH FD for filtering.

Simpler approach: use kernel task struct PID tracking, correlate via timestamps:
- Interceptor logs `action_id: {start_ts}` before tool call
- Collector uses start_ts + end_ts window to cluster syscalls
- No shared maps needed — pure timestamp correlation

## Signature Generation

```python
def sign_syscall_trace(action_id: str, syscalls: list[dict], env_hash: str) -> str:
    """
    Sign a syscall trace for a specific action.
    sig_payload = action_id || sha256(syscall_json) || env_hash
    Returns: Ed25519 signature over sig_payload
    """
    syscall_json = json.dumps(syscalls, sort_keys=True, separators=(',', ':'))
    syscall_hash = sha256(syscall_json.encode())
    sig_payload = f"{action_id}{syscall_hash}{env_hash}"
    return ed25519_sign(sig_payload, collector_private_key)
```

## Verification Logic

```python
def verify_three_signal(receipt: dict, trace: dict) -> tuple[bool, str]:
    """Return (valid, reason)"""
    agent_ok  = verify_agent_claim(receipt)
    host_ok   = verify_host_observation(receipt)
    trace_ok  = verify_syscall_trace(receipt, trace)
    
    signals = [agent_ok, host_ok, trace_ok]
    if sum(signals) >= 2:
        return True, "2-of-3 threshold met"
    else:
        return False, f"Only {sum(signals)}/3 signals valid"
```

## Open Questions

1. **PID reuse**: After agent exits and new process reuses PID, old traces could be misattributed. Mitigated by including `start_time` (kernel boot-time timestamp) alongside PID.

2. **Container namespaces**: Agent may run in a container with PID namespace. eBPF `bpf_get_current_pid_tgid()` returns container-local PID. Need to join with cgroup ID for stable identification.

3. **Performance overhead**: eBPF syscall tracing at high frequency (e.g., 100k syscalls/sec) adds measurable overhead. Benchmarks needed. Filter aggressively.

4. **Verifier trust**: Who verifies the trace signature? Third parties need collector's public key. Option: collector key registered in the transparency log alongside policy commitment.

## Implementation Phases

### Phase 1: Minimal viable tracer (this spec)
- eBPF program filtering openat, connect, sendto
- Userspace collector via ring buffer
- Timestamp-based action correlation
- Signature over trace entries
- Bundle integration in `build_bundle(..., syscall_traces=...)`

### Phase 2: Zero-copy with BPF_MAP_TYPE_RINGBUF
- Already designed above — use ring buffer not perf buffer

### Phase 3: Container-aware PID correlation
- Track cgroup ID alongside PID
- Validate agent's cgroup membership via `/proc/[pid]/cgroup`

### Phase 4: eBPF verifier in kernel
- Use `bpf_check()` loader to validate trace integrity
- Requires custom kernel module — defer

## References
- BPF ring buffer: `man bpf_ringbuf`
- eBPF syscall attach: `man bpf_syscall`
- Linux kernel task struct: `include/linux/sched.h`
