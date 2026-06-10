"""
PACT Syscall Collector Daemon

Consumes syscall trace entries from the eBPF ring buffer,
assembles per-action_id traces, signs with collector key,
and publishes to the configured transparency log.

Run as a daemon: python3 -m pact.collector --pid <agent_pid>
Or as a server: python3 -m pact.collector --socket /run/pact/collector.sock
"""

import struct
import json
import time
import socket
import os
import hashlib
import argparse
from pathlib import Path
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Optional

try:
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from cryptography.hazmat.primitives import serialization
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False


SYS_CALL_NAMES = {
    0: "read", 1: "write", 2: "open", 3: "close", 4: "stat",
    5: "fstat", 8: "lseek", 9: "mmap", 10: "mprotect", 11: "munmap",
    14: "writev", 15: "pread64", 16: "pwrite64", 19: "preadv", 20: "pwritev",
    21: "access", 32: "dup", 33: "dup2", 34: "pause", 35: "nanosleep",
    36: "getpid", 37: "send", 38: "recv", 39: "socket", 40: "connect",
    41: "accept", 42: "sendto", 43: "recvfrom", 44: "sendmsg", 45: "recvmsg",
    46: "shutdown", 47: "bind", 48: "listen", 49: "getsockname",
    50: "getpeername", 51: "socketpair", 52: "setsockopt", 53: "getsockopt",
    54: "clone", 55: "fork", 56: "vfork", 57: "execve", 58: "exit",
    59: "wait4", 60: "kill", 61: "uname", 62: "semget", 63: "semop",
    64: "semctl", 65: "shmget", 66: "shmctl", 67: "shmat", 68: "shmdt",
    69: "sigaction", 70: "sigreturn", 71: "sigprocmask", 72: "sigpending",
    73: "sigtimedwait", 74: "sigwaitinfo", 75: "rt_sigsuspend",
    79: "readlink", 80: "uselib", 81: "readlinkat", 82: "mknod",
    83: "mknodat", 84: "chmod", 85: "fchmod", 86: "fchmodat",
    87: "fchown", 88: "fchownat", 89: "fchownat", 90: "umask",
    91: "gettimeofday", 92: "getrlimit", 93: "getrusage", 94: "sysinfo",
    95: "times", 96: "getuid", 98: "getgid", 100: "setuid", 101: "setgid",
    102: "geteuid", 103: "getegid", 104: "getpgid", 105: "setpgid",
    106: "getpgrp", 107: "setpgrp", 108: "setreuid", 109: "setregid",
    110: "getuid", 111: "syslog", 112: "getgid", 113: "setuid",
    114: "setgid", 115: "setreuid", 116: "setregid", 117: "getgroups",
    118: "setgroups", 119: "setresuid", 120: "getresuid", 121: "setresgid",
    122: "getresgid", 123: "getpgid", 124: "setpgid", 125: "setfsuid",
    126: "setfsgid", 127: "getsid", 128: "setsid", 129: "rt_sigaction",
    130: "rt_sigreturn", 131: "rt_sigprocmask", 132: "rt_sigpending",
    133: "rt_sigtimedwait", 134: "rt_sigwaitinfo", 135: "rt_sigsuspend",
    137: "lchown", 138: "getcwd", 139: "chdir", 140: "fchdir",
    141: "chmod", 142: "fchmod", 143: "fchown", 144: "chown",
    145: "lchown", 146: "umask", 147: "gettimeofday", 148: "getrlimit",
    149: "getrusage", 150: "getgroups", 151: "setgroups", 152: "setresuid",
    153: "getresuid", 154: "setresgid", 155: "getresgid", 156: "getpid",
    157: "getppid", 158: "getpgrp", 159: "setsid", 160: "rt_sigaction",
    161: "rt_sigtimedwait", 162: "rt_sigwaitinfo", 163: "rt_sigsuspend",
    217: "getdents64", 231: "exit_group", 233: "rt_sigreturn",
    234: "arch_prctl", 257: "create_file", 262: "delete_module",
    263: "capget", 264: "capset", 268: "pread64", 269: "pwrite64",
    272: "quotactl", 273: "getdents", 274: "setns", 275: "unshare",
    278: "mkdirat", 279: "mknodat", 280: "fchownat", 281: "futimesat",
    282: "utimensat", 284: "openat", 285: "mkdirat", 286: "mknodat",
    288: "fchownat", 289: "futimesat", 290: "utimensat", 292: "openat",
    293: "create_file", 294: "fstatat", 295: "fstat", 296: "fstatfs",
    297: "fstatfs", 318: "setns", 319: "gettid", 320: "reboot",
    321: "bind", 322: "kairos", 323: "ioctl", 324: "io_setup",
    325: "io_destroy", 326: "io_submit", 327: "io_cancel", 328: "io_getevents",
    329: "set_tid_address", 330: "fadvise64", 410: "pselect6", 411: "ppoll",
    412: "io_setup", 413: "io_destroy", 414: "io_submit", 415: "io_getevents",
    500: "bpf", 501: "userfaultfd", 502: "futex", 503: "inotify_init",
    504: "inotify_add_watch", 505: "inotify_rm_watch", 506: "mbind",
    507: "set_mempolicy", 508: "migrate_pages", 509: "get_mempolicy",
    511: "exit_group",
}

RELEVANT_SYSCALLS = {0, 1, 2, 3, 9, 10, 11, 21, 39, 40, 41, 42, 43, 44, 45,
                     46, 47, 48, 49, 50, 52, 53, 56, 57, 59, 64, 72, 80, 81,
                     84, 85, 86, 87, 88, 89, 91, 92, 93, 96, 98, 102, 103,
                     104, 105, 110, 117, 118, 119, 127, 129, 134, 138, 139,
                     140, 147, 148, 149, 150, 151, 153, 155, 156, 157, 158,
                     159, 160, 161, 162, 163, 217, 231, 257, 262, 263, 264,
                     272, 273, 274, 275, 278, 279, 280, 281, 282, 284, 285,
                     286, 290, 292, 293, 294, 295, 296, 297, 318, 319, 323,
                     410, 411, 500, 501, 502, 503, 504, 505}


@dataclass
class SyscallEntry:
    syscall_id: int
    timestamp_ns: int
    pid: int
    tid: int
    args: dict
    return_val: Optional[int] = None
    action_id: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "syscall": SYS_CALL_NAMES.get(self.syscall_id, f"sys_{self.syscall_id}"),
            "id": self.syscall_id,
            "ts_ns": self.timestamp_ns,
            "pid": self.pid,
            "tid": self.tid,
            "args": self.args,
            "ret": self.return_val,
            "action_id": self.action_id,
        }


@dataclass
class SyscallTrace:
    action_id: str
    agent_pid: int
    start_ts_ns: int
    end_ts_ns: int
    entries: list = field(default_factory=list)
    collector_key: Optional[str] = None
    collector_sig: Optional[str] = None

    def add_entry(self, entry: SyscallEntry):
        entry.action_id = self.action_id
        self.entries.append(entry)

    def finalize(self, end_ts_ns: int):
        self.end_ts_ns = end_ts_ns

    def to_dict(self) -> dict:
        return {
            "action_id": self.action_id,
            "agent_pid": self.agent_pid,
            "start_ts_ns": self.start_ts_ns,
            "end_ts_ns": self.end_ts_ns,
            "syscalls": [e.to_dict() for e in self.entries],
            "count": len(self.entries),
        }

    def compute_hash(self) -> str:
        payload = json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(payload.encode()).hexdigest()

    def sign(self, private_key_bytes: bytes) -> str:
        if not HAS_CRYPTO:
            raise RuntimeError("cryptography not installed")
        key = ed25519.Ed25519PrivateKey.from_private_bytes(private_key_bytes)
        msg = self.compute_hash().encode()
        sig = key.sign(msg)
        return sig.hex()


def read_ring_buffer(ringbuf_fd: int, page_size: int = 4096) -> list:
    """
    Read raw syscall records from eBPF ring buffer fd.
    Layout: struct bpf_ringbuf_hdr + record data.
    Returns list of raw dicts (unpacked by struct.unpack).
    """
    records = []
    buf = os.read(ringbuf_fd, page_size * 8)
    pos = 0
    while pos < len(buf):
        hdr = struct.unpack("IIQ", buf[pos:pos+20])
        len_, pg_off, flags = hdr
        if len_ == 0 or len_ > page_size:
            break
        data = buf[pos+20:pos+20+len_]
        pos += (20 + len_ + 7) // 8 * 8
        if len(data) < 40:
            continue
        try:
            record = struct.unpack("qqqIIII", data[:40])
            syscall_id, timestamp_ns, pid, tid, a0, a1, a1_high = record[0], record[1], record[2], record[3], record[4], record[5], record[6]
            entry = SyscallEntry(
                syscall_id=syscall_id,
                timestamp_ns=timestamp_ns,
                pid=pid,
                tid=tid,
                args={"a0": a0, "a1": a1, "a1_hi": a1_high},
                return_val=None,
            )
            records.append(entry)
        except struct.error:
            continue
    return records


class SyscallCollector:
    """
    Main collector class. Connects to the eBPF ring buffer consumer socket,
    assembles traces per action_id, signs them, and publishes to transparency log.
    """

    def __init__(
        self,
        agent_pid: int,
        collector_key_path: Optional[str] = None,
        log_adapter=None,
        log_url: Optional[str] = None,
        ringbuf_path: Optional[str] = None,
    ):
        self.agent_pid = agent_pid
        self.ringbuf_path = ringbuf_path or f"/sys/kernel/debug/tracing/ring_buffer/pact_syscall_{agent_pid}"
        self.log_adapter = log_adapter
        self.log_url = log_url
        self._traces: dict[str, SyscallTrace] = {}
        self._private_key: Optional[bytes] = None
        self._public_key: Optional[str] = None
        self._running = False

        if collector_key_path and HAS_CRYPTO:
            pk_path = Path(collector_key_path)
            if pk_path.exists():
                self._private_key = pk_path.read_bytes()
                pub_key = ed25519.Ed25519PublicKey.from_private_bytes(self._private_key)
                self._public_key = pub_key.public_bytes(
                    serialization.Encoding.Raw,
                    serialization.PublicFormat.Raw
                ).hex()

    @property
    def public_key(self) -> Optional[str]:
        return self._public_key

    def start(self, duration_s: Optional[int] = None):
        """
        Main loop: consume ring buffer, assemble traces, sign and publish.
        If duration_s is None, runs indefinitely.
        """
        self._running = True
        start_time = time.time()
        sock_path = f"/tmp/pact_ringbuf_{self.agent_pid}"
        start_ts = int(time.time() * 1e9)

        try:
            os.unlink(sock_path)
        except FileNotFoundError:
            pass

        server = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        server.bind(sock_path)
        server.settimeout(0.5)

        print(f"[collector] listening on {sock_path} for PID {self.agent_pid}")
        print(f"[collector] public key: {self._public_key[:16]}... (truncated)")

        while self._running:
            if duration_s and (time.time() - start_time) > duration_s:
                break
            try:
                data, _ = server.recvfrom(4096)
                entries = self._parse_packet(data)
                for entry in entries:
                    if entry.syscall_id not in RELEVANT_SYSCALLS:
                        continue
                    action_id = entry.args.get("action_id", f"action_{entry.pid}_{entry.timestamp_ns}")
                    trace = self._traces.get(action_id)
                    if trace is None:
                        trace = SyscallTrace(
                            action_id=action_id,
                            agent_pid=self.agent_pid,
                            start_ts_ns=entry.timestamp_ns,
                            end_ts_ns=entry.timestamp_ns,
                        )
                        self._traces[action_id] = trace
                    trace.add_entry(entry)
                    trace.end_ts_ns = entry.timestamp_ns
            except socket.timeout:
                continue

        self._flush_all()
        print(f"[collector] stopped. Flushed {len(self._traces)} traces.")

    def _parse_packet(self, data: bytes) -> list:
        records = []
        pos = 0
        while pos < len(data):
            try:
                sz = struct.unpack("I", data[pos:pos+4])[0]
                if sz == 0 or sz > 256:
                    break
                record_data = data[pos+4:pos+4+sz]
                pos += 4 + sz
                if len(record_data) < 32:
                    continue
                vals = struct.unpack("qqqIIII", record_data[:40])
                entry = SyscallEntry(
                    syscall_id=vals[0],
                    timestamp_ns=vals[1],
                    pid=vals[2],
                    tid=vals[3],
                    args={"a0": vals[4], "a1": vals[5]},
                    return_val=None,
                )
                records.append(entry)
            except (struct.error, IndexError):
                continue
        return records

    def _flush_all(self):
        for action_id, trace in list(self._traces.items()):
            if self._private_key:
                trace.collector_key = self._public_key
                trace.collector_sig = trace.sign(self._private_key)
            self._publish(trace)
            del self._traces[action_id]

    def _publish(self, trace: SyscallTrace):
        payload = trace.to_dict()
        payload["_collector_sig"] = trace.collector_sig
        payload["_collector_key"] = trace.collector_key
        payload["_published_at"] = datetime.now(timezone.utc).isoformat()
        payload["_pact_version"] = "1.0.0"

        if self.log_adapter:
            try:
                receipt = self.log_adapter.append_receipt(
                    namespace="pact-syscall",
                    payload=payload,
                )
                print(f"[collector] published trace for {trace.action_id}: {receipt.get('uri', 'no-uri')}")
                return receipt
            except Exception as e:
                print