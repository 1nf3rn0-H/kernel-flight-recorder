"""Embedded eBPF program for the threat hunter sensor."""

BPF_TEXT = """
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
#define AF_ALG 38
#define AF_RXRPC 33
#define AF_NETLINK 16
#define AF_INET 2
#define SOCK_DGRAM 2
#define SOL_ALG 279
#define SOL_RXRPC 272
#define SOL_UDP 17
#define UDP_ENCAP 100
#define NETLINK_XFRM 6
#define CLONE_NEWNS 0x00020000
#define CLONE_NEWUSER 0x10000000
#define CLONE_NEWNET 0x40000000
#define ALG_TYPE_LEN 14
#define ALG_NAME_LEN 64

typedef s32 key_serial_t;

enum event_type {
    EVENT_EXEC = 1,
    EVENT_CONNECT = 2,
    EVENT_MEMFD = 3,
    EVENT_MPROTECT = 4,
    EVENT_VM_WRITE = 5,
    EVENT_AF_ALG_SOCKET = 6,
    EVENT_AF_ALG_BIND = 7,
    EVENT_SOL_ALG_SETSOCKOPT = 8,
    EVENT_AF_ALG_SENDMSG = 9,
    EVENT_AF_ALG_SPLICE = 10,
    EVENT_AF_ALG_ACCEPT = 11,
    EVENT_SUSPICIOUS_SOCKET = 12,
    EVENT_SUSPICIOUS_SETSOCKOPT = 13,
    EVENT_SPLICE = 14,
    EVENT_VMSPLICE = 15,
    EVENT_UNSHARE = 16,
    EVENT_ADD_KEY = 17,
    EVENT_KEYCTL = 18,
    EVENT_RXRPC_BIND = 19,
    EVENT_RXRPC_SENDMSG = 20,
    EVENT_SUSPICIOUS_SOCKET_SEND = 21
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

struct sockaddr_alg_min {
    u16 salg_family;
    unsigned char salg_type[ALG_TYPE_LEN];
    u32 salg_feat;
    u32 salg_mask;
    unsigned char salg_name[ALG_NAME_LEN];
};

struct sockaddr_rxrpc_min {
    u16 srx_family;
    u16 srx_service;
    u16 transport_type;
    u16 transport_len;
};

struct socket_args_t {
    u32 family;
    u32 type;
    u32 protocol;
};

struct fd_key_t {
    u32 pid;
    s32 fd;
};

struct fd_info_t {
    u32 family;
    u32 socket_type;
    u32 protocol;
};

struct accept_args_t {
    s32 fd;
};

struct af_alg_socket_data_t {
    struct common_t common;
    s32 fd;
    u32 family;
    u32 socket_type;
    u32 protocol;
};

struct af_alg_bind_data_t {
    struct common_t common;
    s32 fd;
    char alg_type[ALG_TYPE_LEN];
    char alg_name[ALG_NAME_LEN];
};

struct sol_alg_setsockopt_data_t {
    struct common_t common;
    s32 fd;
    s32 optname;
    u64 optlen;
};

struct af_alg_sendmsg_data_t {
    struct common_t common;
    s32 fd;
    u32 flags;
};

struct af_alg_splice_data_t {
    struct common_t common;
    s32 fd_in;
    s32 fd_out;
    u64 len;
    u32 flags;
    u32 alg_fd_role;
};

struct af_alg_accept_data_t {
    struct common_t common;
    s32 listen_fd;
    s32 accepted_fd;
};

struct suspicious_socket_data_t {
    struct common_t common;
    s32 fd;
    u32 family;
    u32 socket_type;
    u32 protocol;
};

struct suspicious_setsockopt_data_t {
    struct common_t common;
    s32 fd;
    s32 level;
    s32 optname;
    u64 optlen;
    u32 family;
    u32 protocol;
};

struct splice_data_t {
    struct common_t common;
    s32 fd_in;
    s32 fd_out;
    u64 len;
    u32 flags;
    u32 af_alg_fd_role;
};

struct vmsplice_data_t {
    struct common_t common;
    s32 fd;
    u64 iovcnt;
    u64 len;
    u32 flags;
    u32 _pad;
};

struct unshare_data_t {
    struct common_t common;
    u64 flags;
};

struct add_key_data_t {
    struct common_t common;
    char key_type[32];
    char description[64];
    u64 payload_len;
    s32 ring_id;
    u32 _pad;
};

struct keyctl_data_t {
    struct common_t common;
    s32 option;
    u64 arg2;
    u64 arg3;
    u64 arg4;
    u64 arg5;
};

struct rxrpc_bind_data_t {
    struct common_t common;
    s32 fd;
    u16 service;
    u16 transport_type;
    u16 transport_len;
    u16 _pad;
};

struct socket_send_data_t {
    struct common_t common;
    s32 fd;
    u32 family;
    u32 protocol;
    u64 len;
    u32 flags;
    u32 _pad;
};

BPF_HASH(tracked_pids, u32, u32);
BPF_HASH(pending_socket, u64, struct socket_args_t);
BPF_HASH(af_alg_fds, struct fd_key_t, u32);
BPF_HASH(socket_fds, struct fd_key_t, struct fd_info_t);
BPF_HASH(pending_af_alg_accept, u64, struct accept_args_t);
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

static __always_inline struct common_t make_common(u32 type) {
    struct common_t common = {};
    common.type = type;
    common.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&common.comm, sizeof(common.comm));
    return common;
}

static __always_inline int is_af_alg_fd(s32 fd) {
    if (fd < 0) return 0;

    struct fd_key_t key = {};
    key.pid = bpf_get_current_pid_tgid() >> 32;
    key.fd = fd;
    return af_alg_fds.lookup(&key) != 0;
}

static __always_inline struct fd_info_t *lookup_socket_fd(s32 fd) {
    if (fd < 0) return 0;

    struct fd_key_t key = {};
    key.pid = bpf_get_current_pid_tgid() >> 32;
    key.fd = fd;
    return socket_fds.lookup(&key);
}

static __always_inline void remember_af_alg_fd(s32 fd) {
    if (fd < 0) return;

    struct fd_key_t key = {};
    u32 val = 1;
    key.pid = bpf_get_current_pid_tgid() >> 32;
    key.fd = fd;
    af_alg_fds.update(&key, &val);
}

static __always_inline void remember_socket_fd(s32 fd, struct socket_args_t *socket_args) {
    if (fd < 0) return;

    struct fd_key_t key = {};
    struct fd_info_t info = {};
    key.pid = bpf_get_current_pid_tgid() >> 32;
    key.fd = fd;
    info.family = socket_args->family;
    info.socket_type = socket_args->type;
    info.protocol = socket_args->protocol;
    socket_fds.update(&key, &info);
}

static __always_inline int is_dirtyfrag_socket(u32 family, u32 socket_type, u32 protocol) {
    if (family == AF_ALG) return 1;
    if (family == AF_RXRPC) return 1;
    if (family == AF_NETLINK && protocol == NETLINK_XFRM) return 1;
    if (family == AF_INET && (socket_type & 0xf) == SOCK_DGRAM) return 1;
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

TRACEPOINT_PROBE(syscalls, sys_enter_socket) {
    if (!is_tracked()) return 0;
    if (!is_dirtyfrag_socket(args->family, args->type, args->protocol)) return 0;

    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct socket_args_t socket_args = {};
    socket_args.family = args->family;
    socket_args.type = args->type;
    socket_args.protocol = args->protocol;
    pending_socket.update(&pid_tgid, &socket_args);
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_socket) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct socket_args_t *socket_args = pending_socket.lookup(&pid_tgid);
    if (!socket_args) return 0;

    s32 fd = args->ret;
    if (fd >= 0) {
        remember_socket_fd(fd, socket_args);
        if (socket_args->family == AF_ALG) {
            remember_af_alg_fd(fd);

            struct af_alg_socket_data_t *data = events.ringbuf_reserve(sizeof(struct af_alg_socket_data_t));
            if (data) {
                data->common = make_common(EVENT_AF_ALG_SOCKET);
                data->fd = fd;
                data->family = socket_args->family;
                data->socket_type = socket_args->type;
                data->protocol = socket_args->protocol;
                events.ringbuf_submit(data, 0);
            }
        } else if (socket_args->family != AF_INET) {
            struct suspicious_socket_data_t *data = events.ringbuf_reserve(sizeof(struct suspicious_socket_data_t));
            if (data) {
                data->common = make_common(EVENT_SUSPICIOUS_SOCKET);
                data->fd = fd;
                data->family = socket_args->family;
                data->socket_type = socket_args->type;
                data->protocol = socket_args->protocol;
                events.ringbuf_submit(data, 0);
            }
        }
    }

    pending_socket.delete(&pid_tgid);
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_bind) {
    if (!is_tracked()) return 0;

    struct sockaddr_alg_min alg = {};
    bpf_probe_read_user(&alg, sizeof(alg), args->umyaddr);
    if (alg.salg_family == AF_ALG || is_af_alg_fd(args->fd)) {
        remember_af_alg_fd(args->fd);

        struct af_alg_bind_data_t *data = events.ringbuf_reserve(sizeof(struct af_alg_bind_data_t));
        if (!data) return 0;

        data->common = make_common(EVENT_AF_ALG_BIND);
        data->fd = args->fd;
        __builtin_memcpy(data->alg_type, alg.salg_type, sizeof(data->alg_type));
        __builtin_memcpy(data->alg_name, alg.salg_name, sizeof(data->alg_name));

        events.ringbuf_submit(data, 0);
        return 0;
    }

    struct fd_info_t *info = lookup_socket_fd(args->fd);
    if (info && info->family == AF_RXRPC) {
        struct sockaddr_rxrpc_min rx = {};
        bpf_probe_read_user(&rx, sizeof(rx), args->umyaddr);

        struct rxrpc_bind_data_t *data = events.ringbuf_reserve(sizeof(struct rxrpc_bind_data_t));
        if (!data) return 0;

        data->common = make_common(EVENT_RXRPC_BIND);
        data->fd = args->fd;
        data->service = rx.srx_service;
        data->transport_type = rx.transport_type;
        data->transport_len = rx.transport_len;
        events.ringbuf_submit(data, 0);
    }
    return 0;
}

static __always_inline int enter_accept_common(s32 fd) {
    if (!is_tracked()) return 0;
    if (!is_af_alg_fd(fd)) return 0;

    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct accept_args_t accept_args = {};
    accept_args.fd = fd;
    pending_af_alg_accept.update(&pid_tgid, &accept_args);
    return 0;
}

static __always_inline int exit_accept_common(s64 ret) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct accept_args_t *accept_args = pending_af_alg_accept.lookup(&pid_tgid);
    if (!accept_args) return 0;

    if (ret >= 0) {
        remember_af_alg_fd((s32)ret);

        struct af_alg_accept_data_t *data = events.ringbuf_reserve(sizeof(struct af_alg_accept_data_t));
        if (data) {
            data->common = make_common(EVENT_AF_ALG_ACCEPT);
            data->listen_fd = accept_args->fd;
            data->accepted_fd = (s32)ret;
            events.ringbuf_submit(data, 0);
        }
    }

    pending_af_alg_accept.delete(&pid_tgid);
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_accept) {
    return enter_accept_common(args->fd);
}

TRACEPOINT_PROBE(syscalls, sys_exit_accept) {
    return exit_accept_common(args->ret);
}

TRACEPOINT_PROBE(syscalls, sys_enter_accept4) {
    return enter_accept_common(args->fd);
}

TRACEPOINT_PROBE(syscalls, sys_exit_accept4) {
    return exit_accept_common(args->ret);
}

TRACEPOINT_PROBE(syscalls, sys_enter_setsockopt) {
    if (!is_tracked()) return 0;

    struct fd_info_t *info = lookup_socket_fd(args->fd);
    int suspicious = 0;
    if (args->level == SOL_ALG || is_af_alg_fd(args->fd)) suspicious = 1;
    if (args->level == SOL_RXRPC) suspicious = 1;
    if (args->level == SOL_UDP && args->optname == UDP_ENCAP) suspicious = 1;
    if (info && (info->family == AF_RXRPC || (info->family == AF_NETLINK && info->protocol == NETLINK_XFRM))) suspicious = 1;
    if (!suspicious) return 0;

    if (args->level == SOL_ALG) {
        remember_af_alg_fd(args->fd);
    }

    if (args->level != SOL_ALG && !is_af_alg_fd(args->fd)) {
        struct suspicious_setsockopt_data_t *data = events.ringbuf_reserve(sizeof(struct suspicious_setsockopt_data_t));
        if (!data) return 0;

        data->common = make_common(EVENT_SUSPICIOUS_SETSOCKOPT);
        data->fd = args->fd;
        data->level = args->level;
        data->optname = args->optname;
        data->optlen = args->optlen;
        data->family = info ? info->family : 0;
        data->protocol = info ? info->protocol : 0;
        events.ringbuf_submit(data, 0);
        return 0;
    }

    struct sol_alg_setsockopt_data_t *data = events.ringbuf_reserve(sizeof(struct sol_alg_setsockopt_data_t));
    if (!data) return 0;

    data->common = make_common(EVENT_SOL_ALG_SETSOCKOPT);
    data->fd = args->fd;
    data->optname = args->optname;
    data->optlen = args->optlen;

    events.ringbuf_submit(data, 0);
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_close) {
    if (!is_tracked()) return 0;

    struct fd_key_t key = {};
    key.pid = bpf_get_current_pid_tgid() >> 32;
    key.fd = args->fd;
    af_alg_fds.delete(&key);
    socket_fds.delete(&key);
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_sendmsg) {
    if (!is_tracked()) return 0;

    struct fd_info_t *info = lookup_socket_fd(args->fd);
    if (!is_af_alg_fd(args->fd) && (!info || info->family != AF_RXRPC)) return 0;

    struct af_alg_sendmsg_data_t *data = events.ringbuf_reserve(sizeof(struct af_alg_sendmsg_data_t));
    if (!data) return 0;

    data->common = make_common(is_af_alg_fd(args->fd) ? EVENT_AF_ALG_SENDMSG : EVENT_RXRPC_SENDMSG);
    data->fd = args->fd;
    data->flags = args->flags;
    events.ringbuf_submit(data, 0);
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_sendto) {
    if (!is_tracked()) return 0;

    struct fd_info_t *info = lookup_socket_fd(args->fd);
    if (!info) return 0;
    if (!(info->family == AF_RXRPC || (info->family == AF_NETLINK && info->protocol == NETLINK_XFRM))) return 0;

    struct socket_send_data_t *data = events.ringbuf_reserve(sizeof(struct socket_send_data_t));
    if (!data) return 0;

    data->common = make_common(EVENT_SUSPICIOUS_SOCKET_SEND);
    data->fd = args->fd;
    data->family = info->family;
    data->protocol = info->protocol;
    data->len = args->len;
    data->flags = args->flags;
    events.ringbuf_submit(data, 0);
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_splice) {
    if (!is_tracked()) return 0;

    int in_is_alg = is_af_alg_fd(args->fd_in);
    int out_is_alg = is_af_alg_fd(args->fd_out);

    struct splice_data_t *data = events.ringbuf_reserve(sizeof(struct splice_data_t));
    if (!data) return 0;

    data->common = make_common(in_is_alg || out_is_alg ? EVENT_AF_ALG_SPLICE : EVENT_SPLICE);
    data->fd_in = args->fd_in;
    data->fd_out = args->fd_out;
    data->len = args->len;
    data->flags = args->flags;
    data->af_alg_fd_role = in_is_alg ? 1 : (out_is_alg ? 2 : 0);

    events.ringbuf_submit(data, 0);
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_vmsplice) {
    if (!is_tracked()) return 0;

    struct vmsplice_data_t *data = events.ringbuf_reserve(sizeof(struct vmsplice_data_t));
    if (!data) return 0;

    data->common = make_common(EVENT_VMSPLICE);
    data->fd = args->fd;
    data->iovcnt = args->nr_segs;
    data->len = 0;
    data->flags = args->flags;

    struct iovec iov = {};
    bpf_probe_read_user(&iov, sizeof(iov), (void *)args->uiov);
    data->len = (u64)iov.iov_len;

    events.ringbuf_submit(data, 0);
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_unshare) {
    if (!is_tracked()) return 0;
    if (!(args->unshare_flags & (CLONE_NEWUSER | CLONE_NEWNET | CLONE_NEWNS))) return 0;

    struct unshare_data_t *data = events.ringbuf_reserve(sizeof(struct unshare_data_t));
    if (!data) return 0;

    data->common = make_common(EVENT_UNSHARE);
    data->flags = args->unshare_flags;
    events.ringbuf_submit(data, 0);
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_add_key) {
    if (!is_tracked()) return 0;

    struct add_key_data_t *data = events.ringbuf_reserve(sizeof(struct add_key_data_t));
    if (!data) return 0;

    data->common = make_common(EVENT_ADD_KEY);
    bpf_probe_read_user_str(&data->key_type, sizeof(data->key_type), args->_type);
    bpf_probe_read_user_str(&data->description, sizeof(data->description), args->_description);
    data->payload_len = args->plen;
    data->ring_id = args->ringid;
    events.ringbuf_submit(data, 0);
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_keyctl) {
    if (!is_tracked()) return 0;

    struct keyctl_data_t *data = events.ringbuf_reserve(sizeof(struct keyctl_data_t));
    if (!data) return 0;

    data->common = make_common(EVENT_KEYCTL);
    data->option = args->option;
    data->arg2 = args->arg2;
    data->arg3 = args->arg3;
    data->arg4 = args->arg4;
    data->arg5 = args->arg5;
    events.ringbuf_submit(data, 0);
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
