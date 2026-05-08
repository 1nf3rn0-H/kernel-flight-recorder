"""Run the sensor with `python -m ebpf_threat_hunter`."""

from .cli import main


if __name__ == "__main__":
    raise SystemExit(main())
