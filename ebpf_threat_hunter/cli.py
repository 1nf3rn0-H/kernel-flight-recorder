"""Command line entrypoint for the eBPF Threat Hunter Sensor."""

import argparse
import ctypes as ct
import sys

from bcc import BPF

from .bpf_program import BPF_TEXT
from .cgroup import get_cgroup_id
from .events import handle_event


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-c",
        "--container",
        type=str,
        required=True,
        help="Docker Container ID or Name to trace",
    )
    args = parser.parse_args(argv)

    cgroup_id = get_cgroup_id(args.container)

    print(f"[*] Compiling eBPF and tracing Cgroup ID {cgroup_id}...")
    try:
        b = BPF(text=BPF_TEXT)
    except Exception as e:
        print(f"[!] Compilation failed: {e}")
        sys.exit(1)

    b["target_cgroup"][ct.c_int(0)] = ct.c_uint64(cgroup_id)

    b["events"].open_ring_buffer(handle_event)

    print("[*] Ring Buffer Active. Hunting threats inside the container...")
    try:
        while True:
            b.ring_buffer_poll()
    except KeyboardInterrupt:
        print("\n[*] Exiting...")
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
