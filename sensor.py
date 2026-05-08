#!/usr/bin/env python3
"""Compatibility wrapper for the packaged eBPF Threat Hunter Sensor."""

from ebpf_threat_hunter.cli import main


if __name__ == "__main__":
    raise SystemExit(main())
