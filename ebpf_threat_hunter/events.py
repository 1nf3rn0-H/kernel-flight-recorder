"""ctypes event definitions and ring-buffer event handling."""

import ctypes as ct
import hashlib
import os
import re
import socket
import struct
from datetime import datetime, timezone

from .logging_utils import emit_log

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

class AFAlgSocketData(ct.Structure):
    _fields_ = [("common", CommonData), ("fd", ct.c_int32), ("family", ct.c_uint32),
                ("socket_type", ct.c_uint32), ("protocol", ct.c_uint32)]

class AFAlgBindData(ct.Structure):
    _fields_ = [("common", CommonData), ("fd", ct.c_int32), ("alg_type", ct.c_char * 14),
                ("alg_name", ct.c_char * 64)]

class SOLAlgSetsockoptData(ct.Structure):
    _fields_ = [("common", CommonData), ("fd", ct.c_int32), ("optname", ct.c_int32),
                ("optlen", ct.c_uint64)]

class AFAlgSendmsgData(ct.Structure):
    _fields_ = [("common", CommonData), ("fd", ct.c_int32), ("flags", ct.c_uint32)]

class AFAlgSpliceData(ct.Structure):
    _fields_ = [("common", CommonData), ("fd_in", ct.c_int32), ("fd_out", ct.c_int32),
                ("length", ct.c_uint64), ("flags", ct.c_uint32), ("alg_fd_role", ct.c_uint32)]

class AFAlgAcceptData(ct.Structure):
    _fields_ = [("common", CommonData), ("listen_fd", ct.c_int32), ("accepted_fd", ct.c_int32)]

class SuspiciousSocketData(ct.Structure):
    _fields_ = [("common", CommonData), ("fd", ct.c_int32), ("family", ct.c_uint32),
                ("socket_type", ct.c_uint32), ("protocol", ct.c_uint32)]

class SuspiciousSetsockoptData(ct.Structure):
    _fields_ = [("common", CommonData), ("fd", ct.c_int32), ("level", ct.c_int32),
                ("optname", ct.c_int32), ("optlen", ct.c_uint64),
                ("family", ct.c_uint32), ("protocol", ct.c_uint32)]

class SpliceData(ct.Structure):
    _fields_ = [("common", CommonData), ("fd_in", ct.c_int32), ("fd_out", ct.c_int32),
                ("length", ct.c_uint64), ("flags", ct.c_uint32), ("af_alg_fd_role", ct.c_uint32)]

class VMSpliceData(ct.Structure):
    _fields_ = [("common", CommonData), ("fd", ct.c_int32), ("iovcnt", ct.c_uint64),
                ("length", ct.c_uint64), ("flags", ct.c_uint32), ("_pad", ct.c_uint32)]

class UnshareData(ct.Structure):
    _fields_ = [("common", CommonData), ("flags", ct.c_uint64)]

class AddKeyData(ct.Structure):
    _fields_ = [("common", CommonData), ("key_type", ct.c_char * 32),
                ("description", ct.c_char * 64), ("payload_len", ct.c_uint64),
                ("ring_id", ct.c_int32), ("_pad", ct.c_uint32)]

class KeyctlData(ct.Structure):
    _fields_ = [("common", CommonData), ("option", ct.c_int32), ("arg2", ct.c_uint64),
                ("arg3", ct.c_uint64), ("arg4", ct.c_uint64), ("arg5", ct.c_uint64)]

class RXRPCBindData(ct.Structure):
    _fields_ = [("common", CommonData), ("fd", ct.c_int32), ("service", ct.c_uint16),
                ("transport_type", ct.c_uint16), ("transport_len", ct.c_uint16),
                ("_pad", ct.c_uint16)]

class SocketSendData(ct.Structure):
    _fields_ = [("common", CommonData), ("fd", ct.c_int32), ("family", ct.c_uint32),
                ("protocol", ct.c_uint32), ("length", ct.c_uint64),
                ("flags", ct.c_uint32), ("_pad", ct.c_uint32)]

EVENT_EXEC = 1
EVENT_CONNECT = 2
EVENT_MEMFD = 3
EVENT_MPROTECT = 4
EVENT_VM_WRITE = 5
EVENT_AF_ALG_SOCKET = 6
EVENT_AF_ALG_BIND = 7
EVENT_SOL_ALG_SETSOCKOPT = 8
EVENT_AF_ALG_SENDMSG = 9
EVENT_AF_ALG_SPLICE = 10
EVENT_AF_ALG_ACCEPT = 11
EVENT_SUSPICIOUS_SOCKET = 12
EVENT_SUSPICIOUS_SETSOCKOPT = 13
EVENT_SPLICE = 14
EVENT_VMSPLICE = 15
EVENT_UNSHARE = 16
EVENT_ADD_KEY = 17
EVENT_KEYCTL = 18
EVENT_RXRPC_BIND = 19
EVENT_RXRPC_SENDMSG = 20
EVENT_SUSPICIOUS_SOCKET_SEND = 21

# --- PYTHON HANDLERS ---
def decode_c_string(raw):
    return bytes(raw).split(b'\x00', 1)[0].decode('utf-8', 'replace')

def socket_family_name(family):
    return {
        2: "AF_INET",
        16: "AF_NETLINK",
        33: "AF_RXRPC",
        38: "AF_ALG",
    }.get(family, str(family))

def socket_protocol_name(family, protocol):
    if family == 16 and protocol == 6:
        return "NETLINK_XFRM"
    if family == 2 and protocol == 17:
        return "IPPROTO_UDP"
    if family == 33:
        return "PF_INET"
    return str(protocol)

def setsockopt_name(level, optname):
    if level == 17 and optname == 100:
        return "UDP_ENCAP"
    if level == 272:
        return "SOL_RXRPC"
    if level == 279:
        return "SOL_ALG"
    return str(optname)

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
    comm_str = decode_c_string(common.comm)

    if common.type == EVENT_EXEC:
        event = ct.cast(data, ct.POINTER(ExecData)).contents
        true_filename = decode_c_string(event.filename)
        arg = decode_c_string(event.arg)
        
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
        log["details"] = {"anonymous_file_name": decode_c_string(event.name)}
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

    elif common.type == EVENT_AF_ALG_SOCKET:
        event = ct.cast(data, ct.POINTER(AFAlgSocketData)).contents
        log = get_base_log("AF_ALG_SOCKET", common.pid, comm_str)
        log["details"] = {
            "fd": event.fd,
            "family": event.family,
            "socket_type": event.socket_type,
            "protocol": event.protocol
        }
        emit_log(log)

    elif common.type == EVENT_AF_ALG_BIND:
        event = ct.cast(data, ct.POINTER(AFAlgBindData)).contents
        log = get_base_log("AF_ALG_BIND", common.pid, comm_str)
        log["details"] = {
            "fd": event.fd,
            "algorithm_type": decode_c_string(event.alg_type),
            "algorithm_name": decode_c_string(event.alg_name)
        }
        emit_log(log)

    elif common.type == EVENT_SOL_ALG_SETSOCKOPT:
        event = ct.cast(data, ct.POINTER(SOLAlgSetsockoptData)).contents
        log = get_base_log("SOL_ALG_SETSOCKOPT", common.pid, comm_str)
        log["details"] = {
            "fd": event.fd,
            "optname": event.optname,
            "optlen": event.optlen
        }
        emit_log(log)

    elif common.type == EVENT_AF_ALG_ACCEPT:
        event = ct.cast(data, ct.POINTER(AFAlgAcceptData)).contents
        log = get_base_log("AF_ALG_ACCEPT", common.pid, comm_str)
        log["details"] = {
            "listen_fd": event.listen_fd,
            "accepted_fd": event.accepted_fd
        }
        emit_log(log)

    elif common.type == EVENT_AF_ALG_SENDMSG:
        event = ct.cast(data, ct.POINTER(AFAlgSendmsgData)).contents
        log = get_base_log("AF_ALG_SENDMSG", common.pid, comm_str)
        log["details"] = {
            "fd": event.fd,
            "flags": event.flags
        }
        emit_log(log)

    elif common.type == EVENT_AF_ALG_SPLICE:
        event = ct.cast(data, ct.POINTER(SpliceData)).contents
        log = get_base_log("AF_ALG_SPLICE", common.pid, comm_str)
        log["details"] = {
            "fd_in": event.fd_in,
            "fd_out": event.fd_out,
            "length_bytes": event.length,
            "flags": event.flags,
            "af_alg_fd_role": "input" if event.af_alg_fd_role == 1 else "output"
        }
        emit_log(log)

    elif common.type == EVENT_SUSPICIOUS_SOCKET:
        event = ct.cast(data, ct.POINTER(SuspiciousSocketData)).contents
        log = get_base_log("SUSPICIOUS_SOCKET", common.pid, comm_str)
        log["details"] = {
            "fd": event.fd,
            "family": socket_family_name(event.family),
            "family_id": event.family,
            "socket_type": event.socket_type,
            "protocol": socket_protocol_name(event.family, event.protocol),
            "protocol_id": event.protocol
        }
        emit_log(log)

    elif common.type == EVENT_SUSPICIOUS_SETSOCKOPT:
        event = ct.cast(data, ct.POINTER(SuspiciousSetsockoptData)).contents
        log = get_base_log("SUSPICIOUS_SETSOCKOPT", common.pid, comm_str)
        log["details"] = {
            "fd": event.fd,
            "level": event.level,
            "optname": setsockopt_name(event.level, event.optname),
            "optname_id": event.optname,
            "optlen": event.optlen,
            "socket_family": socket_family_name(event.family),
            "socket_protocol": socket_protocol_name(event.family, event.protocol)
        }
        emit_log(log)

    elif common.type == EVENT_SPLICE:
        event = ct.cast(data, ct.POINTER(SpliceData)).contents
        log = get_base_log("SPLICE", common.pid, comm_str)
        log["details"] = {
            "fd_in": event.fd_in,
            "fd_out": event.fd_out,
            "length_bytes": event.length,
            "flags": event.flags
        }
        emit_log(log)

    elif common.type == EVENT_VMSPLICE:
        event = ct.cast(data, ct.POINTER(VMSpliceData)).contents
        log = get_base_log("VMSPLICE", common.pid, comm_str)
        log["details"] = {
            "fd": event.fd,
            "iov_count": event.iovcnt,
            "first_iov_length_bytes": event.length,
            "flags": event.flags
        }
        emit_log(log)

    elif common.type == EVENT_UNSHARE:
        event = ct.cast(data, ct.POINTER(UnshareData)).contents
        log = get_base_log("UNSHARE_NAMESPACE", common.pid, comm_str)
        log["details"] = {
            "flags": hex(event.flags),
            "new_user_namespace": bool(event.flags & 0x10000000),
            "new_network_namespace": bool(event.flags & 0x40000000),
            "new_mount_namespace": bool(event.flags & 0x00020000)
        }
        emit_log(log)

    elif common.type == EVENT_ADD_KEY:
        event = ct.cast(data, ct.POINTER(AddKeyData)).contents
        log = get_base_log("ADD_KEY", common.pid, comm_str)
        log["details"] = {
            "key_type": decode_c_string(event.key_type),
            "description": decode_c_string(event.description),
            "payload_len": event.payload_len,
            "ring_id": event.ring_id
        }
        emit_log(log)

    elif common.type == EVENT_KEYCTL:
        event = ct.cast(data, ct.POINTER(KeyctlData)).contents
        log = get_base_log("KEYCTL", common.pid, comm_str)
        log["details"] = {
            "option": event.option,
            "arg2": event.arg2,
            "arg3": event.arg3,
            "arg4": event.arg4,
            "arg5": event.arg5
        }
        emit_log(log)

    elif common.type == EVENT_RXRPC_BIND:
        event = ct.cast(data, ct.POINTER(RXRPCBindData)).contents
        log = get_base_log("RXRPC_BIND", common.pid, comm_str)
        log["details"] = {
            "fd": event.fd,
            "service": event.service,
            "transport_type": event.transport_type,
            "transport_len": event.transport_len
        }
        emit_log(log)

    elif common.type == EVENT_RXRPC_SENDMSG:
        event = ct.cast(data, ct.POINTER(AFAlgSendmsgData)).contents
        log = get_base_log("RXRPC_SENDMSG", common.pid, comm_str)
        log["details"] = {
            "fd": event.fd,
            "flags": event.flags
        }
        emit_log(log)

    elif common.type == EVENT_SUSPICIOUS_SOCKET_SEND:
        event = ct.cast(data, ct.POINTER(SocketSendData)).contents
        log = get_base_log("SUSPICIOUS_SOCKET_SEND", common.pid, comm_str)
        log["details"] = {
            "fd": event.fd,
            "family": socket_family_name(event.family),
            "family_id": event.family,
            "protocol": socket_protocol_name(event.family, event.protocol),
            "protocol_id": event.protocol,
            "length_bytes": event.length,
            "flags": event.flags
        }
        emit_log(log)

