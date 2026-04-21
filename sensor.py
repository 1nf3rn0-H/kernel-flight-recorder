#!/usr/bin/env python3
from bcc import BPF
import argparse
import sys
import ctypes as ct
import socket
import struct
import json
import logging
import hashlib
import os
import subprocess
import re
from datetime import datetime, timezone

# --- LOGGING SETUP ---
LOG_FILE = "ebpf_sensor.log"
logging.basicConfig(filename=LOG_FILE, level=logging.INFO, format='%(message)s')

def emit_log(log_dict):
    json_log = json.dumps(log_dict)
    logging.info(json_log)
    print(json_log)

# --- DOCKER CGROUP RESOLVER ---
def get_cgroup_id(container_name_or_id):
    try:
        full_id = subprocess.check_output(
            ['docker', 'inspect', '--format', '{{.Id}}', container_name_or_id], 
            stderr=subprocess.STDOUT
        ).decode().strip()
        
        cgroup_path = f"/sys/fs/cgroup/system.slice/docker-{full_id}.scope"
        if not os.path.exists(cgroup_path):
            cgroup_path = f"/sys/fs/cgroup/docker/{full_id}"
            
        if not os.path.exists(cgroup_path):
            raise FileNotFoundError(f"Could not find cgroup directory for {full_id}. Is the container running?")

        cgroup_id = os.stat(cgroup_path).st_ino
        print(f"[*] Resolved Container '{container_name_or_id}' -> Full ID: {full_id[:12]}... -> Cgroup ID: {cgroup_id}")
        return cgroup_id
        
    except subprocess.CalledProcessError:
        print(f"[!] Docker error: Container '{container_name_or_id}' not found.")
        sys.exit(1)
    except Exception as e:
        print(f"[!] Cgroup resolution failed: {e}")
        sys.exit(1)

# --- eBPF C CODE ---
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/socket.h>
#include <linux/in.h>
#include <linux/mm_types.h>
#include <linux/uio.h>

#define ARGSIZE  128
#define MAXARGS  6
#define FNAME_LEN 256
#define PROT_EXEC 4

enum event_type {
    EVENT_EXEC = 1,
    EVENT_CONNECT = 2,
    EVENT_MEMFD = 3,
    EVENT_MPROTECT = 4,
    EVENT_VM_WRITE = 5
};

// Base structure for all events
struct common_t {
    u32 type;
    u32 pid;
    char comm[TASK_COMM_LEN];
};

struct exec_data_t {
    struct common_t common;
    char filename[FNAME_LEN];
    char arg[ARGSIZE];
};

struct connect_data_t {
    struct common_t common;
    u32 ip;
    u16 port;
    u16 _pad;
};

struct memfd_data_t {
    struct common_t common;
    char name[FNAME_LEN];
};

struct mprotect_data_t {
    struct common_t common;
    u64 addr;
    u64 len;
    u32 prot;
    u32 _pad;
};

struct vm_write_data_t {
    struct common_t common;
    u32 target_pid;
    u32 _pad;
    u64 remote_addr;
    u64 local_addr;
    u64 bytes;
};

BPF_HASH(tracked_pids, u32, u32);
BPF_ARRAY(target_cgroup, u64, 1);
BPF_RINGBUF_OUTPUT(events, 1024); // Shared Ring Buffer

static __always_inline int is_tracked() {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    if (tracked_pids.lookup(&pid)) return 1;

    int zero = 0;
    u64 *cgroup_ptr = target_cgroup.lookup(&zero);
    if (cgroup_ptr && *cgroup_ptr != 0) {
        if (bpf_get_current_cgroup_id() == *cgroup_ptr) {
            u32 val = 1;
            tracked_pids.update(&pid, &val);
            return 1;
        }
    }
    return 0;
}

TRACEPOINT_PROBE(sched, sched_process_fork) {
    u32 parent_pid = args->parent_pid;
    u32 child_pid = args->child_pid;
    if (tracked_pids.lookup(&parent_pid)) {
        u32 val = 1;
        tracked_pids.update(&child_pid, &val);
    }
    return 0;
}

TRACEPOINT_PROBE(sched, sched_process_exit) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    tracked_pids.delete(&pid);
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_execve) {
    if (!is_tracked()) return 0;

    struct exec_data_t *data = events.ringbuf_reserve(sizeof(struct exec_data_t));
    if (!data) return 0;

    data->common.type = EVENT_EXEC;
    data->common.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&data->common.comm, sizeof(data->common.comm));
    bpf_probe_read_user_str(&data->filename, sizeof(data->filename), args->filename);

    const char **argv = (const char **)(args->argv);
    const char *argp;
    bpf_probe_read_user(&argp, sizeof(argp), &argv[1]); // Grabbing 1st arg for brevity
    if (argp) {
        bpf_probe_read_user_str(&data->arg, sizeof(data->arg), argp);
    } else {
        data->arg[0] = '\\0';
    }

    events.ringbuf_submit(data, 0);
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_connect) {
    if (!is_tracked()) return 0;
    
    struct sockaddr_in addr = {};
    bpf_probe_read_user(&addr, sizeof(addr), args->uservaddr);
    
    if (addr.sin_family == 2) {
        struct connect_data_t *data = events.ringbuf_reserve(sizeof(struct connect_data_t));
        if (!data) return 0;

        data->common.type = EVENT_CONNECT;
        data->common.pid = bpf_get_current_pid_tgid() >> 32;
        bpf_get_current_comm(&data->common.comm, sizeof(data->common.comm));
        data->ip = addr.sin_addr.s_addr;
        data->port = addr.sin_port;

        events.ringbuf_submit(data, 0);
    }
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_memfd_create) {
    if (!is_tracked()) return 0;
    
    struct memfd_data_t *data = events.ringbuf_reserve(sizeof(struct memfd_data_t));
    if (!data) return 0;

    data->common.type = EVENT_MEMFD;
    data->common.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&data->common.comm, sizeof(data->common.comm));
    bpf_probe_read_user_str(&data->name, sizeof(data->name), args->uname);
    
    events.ringbuf_submit(data, 0);
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_mprotect) {
    u32 prot = args->prot;
    if (!(prot & PROT_EXEC)) return 0; 
    if (!is_tracked()) return 0;
    
    struct mprotect_data_t *data = events.ringbuf_reserve(sizeof(struct mprotect_data_t));
    if (!data) return 0;

    data->common.type = EVENT_MPROTECT;
    data->common.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&data->common.comm, sizeof(data->common.comm));
    data->addr = args->start;
    data->len = args->len;
    data->prot = prot;

    events.ringbuf_submit(data, 0);
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_process_vm_writev) {
    if (!is_tracked()) return 0;
    
    struct vm_write_data_t *data = events.ringbuf_reserve(sizeof(struct vm_write_data_t));
    if (!data) return 0;

    data->common.type = EVENT_VM_WRITE;
    data->common.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&data->common.comm, sizeof(data->common.comm));
    data->target_pid = args->pid;

    struct iovec iov;
    bpf_probe_read_user(&iov, sizeof(iov), (void *)args->lvec);
    data->local_addr = (u64)iov.iov_base;
    
    bpf_probe_read_user(&iov, sizeof(iov), (void *)args->rvec);
    data->remote_addr = (u64)iov.iov_base;
    data->bytes = (u64)iov.iov_len;
    
    events.ringbuf_submit(data, 0);
    return 0;
}
"""

# --- PYTHON CTYPES DEFINITIONS ---
class CommonData(ct.Structure):
    _fields_ = [("type", ct.c_uint32), ("pid", ct.c_uint32), ("comm", ct.c_char * 16)]

class ExecData(ct.Structure):
    _fields_ = [("common", CommonData), ("filename", ct.c_char * 256), ("arg", ct.c_char * 128)]

class ConnectData(ct.Structure):
    _fields_ = [("common", CommonData), ("ip", ct.c_uint32), ("port", ct.c_uint16), ("_pad", ct.c_uint16)]

class MemfdData(ct.Structure):
    _fields_ = [("common", CommonData), ("name", ct.c_char * 256)]

class MprotectData(ct.Structure):
    _fields_ = [("common", CommonData), ("addr", ct.c_uint64), ("len", ct.c_uint64), ("prot", ct.c_uint32), ("_pad", ct.c_uint32)]

class VMWriteData(ct.Structure):
    _fields_ = [("common", CommonData), ("target_pid", ct.c_uint32), ("_pad", ct.c_uint32), 
                ("remote_addr", ct.c_uint64), ("local_addr", ct.c_uint64), ("bytes", ct.c_uint64)]

EVENT_EXEC = 1
EVENT_CONNECT = 2
EVENT_MEMFD = 3
EVENT_MPROTECT = 4
EVENT_VM_WRITE = 5

# --- PYTHON HANDLERS ---
def get_base_log(event_type, pid, comm):
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(), 
        "sensor_type": "ebpf_threat_hunter", 
        "event_type": event_type, 
        "actor": {"pid": pid, "process_name": comm}
    }

def handle_event(ctx, data, size):
    # Peek at the common header
    common = ct.cast(data, ct.POINTER(CommonData)).contents
    comm_str = common.comm.decode('utf-8', 'replace')

    if common.type == EVENT_EXEC:
        event = ct.cast(data, ct.POINTER(ExecData)).contents
        true_filename = event.filename.decode('utf-8', 'replace')
        arg = event.arg.decode('utf-8', 'replace')
        
        log = get_base_log("EXECVE", common.pid, comm_str)
        log["details"] = {"true_path": true_filename, "first_arg": arg}
        
        match = re.search(r'/proc/(self|\d+)/fd/(\d+)', true_filename)
        if match:
            fd_num = match.group(2)
            host_fd_path = f"/proc/{common.pid}/fd/{fd_num}"
            payload_info = {"status": "extraction_failed"}
            try:
                with open(host_fd_path, 'rb') as fd_file:
                    payload = fd_file.read()
                    if payload:
                        dump_name = f"dump_memfd_{common.pid}_fd{fd_num}.bin"
                        with open(dump_name, 'wb') as dump_file:
                            dump_file.write(payload)
                        payload_info.update({
                            "status": "extracted",
                            "artifact_path": os.path.abspath(dump_name),
                            "sha256": hashlib.sha256(payload).hexdigest(),
                            "preview": payload[:50].decode('utf-8', 'replace').strip()
                        })
            except Exception as e:
                payload_info["error"] = str(e)
            log["fileless_payload"] = payload_info
        emit_log(log)

    elif common.type == EVENT_CONNECT:
        event = ct.cast(data, ct.POINTER(ConnectData)).contents
        ip_str = socket.inet_ntoa(struct.pack("<I", event.ip))
        port = socket.ntohs(event.port)
        log = get_base_log("NETWORK_CONNECT", common.pid, comm_str)
        log["details"] = {"destination_ip": ip_str, "destination_port": port}
        emit_log(log)

    elif common.type == EVENT_MEMFD:
        event = ct.cast(data, ct.POINTER(MemfdData)).contents
        log = get_base_log("MEMFD_CREATE", common.pid, comm_str)
        log["details"] = {"anonymous_file_name": event.name.decode('utf-8', 'replace')}
        emit_log(log)

    elif common.type == EVENT_MPROTECT:
        event = ct.cast(data, ct.POINTER(MprotectData)).contents
        log = get_base_log("MPROTECT_EXEC", common.pid, comm_str)
        log["details"] = {"memory_address": hex(event.addr), "length_bytes": event.len}
        emit_log(log)

    elif common.type == EVENT_VM_WRITE:
        event = ct.cast(data, ct.POINTER(VMWriteData)).contents
        log = get_base_log("PROCESS_VM_WRITEV", common.pid, comm_str)
        log["target"] = {"pid": event.target_pid, "memory_address": hex(event.remote_addr)}
        
        payload_info = {"bytes_injected": event.bytes, "status": "extraction_failed"}
        mem_path = f"/proc/{common.pid}/mem"
        output_file = f"dump_injector_{common.pid}_{hex(event.local_addr)}.bin"
        
        try:
            with open(mem_path, 'rb') as mem_file:
                mem_file.seek(event.local_addr)
                payload = mem_file.read(event.bytes)
                if payload:
                    with open(output_file, 'wb') as out:
                        out.write(payload)
                    payload_info.update({
                        "status": "extracted_from_source",
                        "artifact_path": os.path.abspath(output_file),
                        "sha256": hashlib.sha256(payload).hexdigest()
                    })
        except Exception as e:
            payload_info["error"] = str(e)

        log["payload"] = payload_info
        emit_log(log)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-c", "--container", type=str, required=True, help="Docker Container ID or Name to trace")
    args = parser.parse_args()

    cgroup_id = get_cgroup_id(args.container)

    print(f"[*] Compiling eBPF and tracing Cgroup ID {cgroup_id}...")
    try:
        b = BPF(text=bpf_text)
    except Exception as e:
        print(f"[!] Compilation failed: {e}")
        sys.exit(1)

    b["target_cgroup"][ct.c_int(0)] = ct.c_uint64(cgroup_id)

    # Attach the unified ring buffer handler
    b["events"].open_ring_buffer(handle_event)

    print("[*] Ring Buffer Active. Hunting threats inside the container...")
    try:
        while True:
            # Polls the shared ring buffer
            b.ring_buffer_poll()
    except KeyboardInterrupt:
        print("\n[*] Exiting...")
        sys.exit(0)