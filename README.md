# Kernel Flight Recorder

An advanced eBPF-based security sensor designed to monitor and detect suspicious activities within Docker containers. This tool leverages the power of eBPF (extended Berkeley Packet Filter) to track process executions, network connections, memory operations, and other potentially malicious behaviors in real-time.

## Features

- **Container-Specific Monitoring**: Targets specific Docker containers using cgroup IDs for precise isolation
- **Real-Time Threat Detection**: Monitors critical syscalls including:
  - Process execution (`execve`)
  - Network connections (`connect`)
  - Anonymous file creation (`memfd_create`) - detects fileless malware
  - Memory protection changes (`mprotect`) - identifies executable memory regions
  - Cross-process memory injection (`process_vm_writev`) - detects code injection attacks
- **Artifact Extraction**: Automatically extracts and dumps suspicious payloads from memory
- **JSON Logging**: Structured logging for easy integration with SIEM systems
- **Fork/Exit Tracking**: Maintains process lineage tracking across container lifecycles

## Prerequisites

- Linux kernel 4.1+ with eBPF support
- Docker installed and running
- Python 3.6+
- BCC (BPF Compiler Collection) installed
- Root privileges (required for eBPF operations)

## Installation

1. **Install BCC**:
   ```bash
   # On Ubuntu/Debian
   sudo apt-get install bcc-tools libbcc-examples linux-headers-$(uname -r)

   # On CentOS/RHEL/Fedora
   sudo yum install bcc-tools
   ```

2. **Install Python dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Clone or download this repository**:
   ```bash
   git clone https://github.com/harsh-mehta/kernel-flight-recorder
   cd kernel-flight-recorder
   ```

## Usage

Run the sensor targeting a specific Docker container:

```bash
sudo python3 sensor.py -c <container_name_or_id>
```

The legacy `sensor.py` wrapper delegates to the package entrypoint. You can also run:

```bash
sudo python3 -m kernel_flight_recorder -c <container_name_or_id>
```

### Examples

```bash
# Monitor a container by name
sudo python3 sensor.py -c my_web_app

# Monitor a container by ID
sudo python3 sensor.py -c a1b2c3d4e5f6
```

The sensor will:
1. Resolve the container's cgroup ID
2. Load the eBPF program
3. Begin monitoring and logging events
4. Extract artifacts when suspicious activity is detected

## Output

Events are logged in JSON format to both console and `ebpf_sensor.log`:

```json
{
  "timestamp": "2023-12-07T10:30:45.123456+00:00",
  "sensor_type": "ebpf_threat_hunter",
  "event_type": "EXECVE",
  "actor": {
    "pid": 1234,
    "process_name": "suspicious_proc"
  },
  "details": {
    "true_path": "/proc/self/fd/5",
    "first_arg": "--malicious-flag"
  },
  "fileless_payload": {
    "status": "extracted",
    "artifact_path": "/path/to/dump_memfd_1234_fd5.bin",
    "sha256": "a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3",
    "preview": "#!/bin/bash\\necho 'Malware detected'"
  }
}
```

## Testing

The `testing samples/` directory contains sample C programs that demonstrate various attack techniques:

- `fileless.c`: Demonstrates fileless execution using memfd
- `injector.c`: Shows process memory injection
- `sample.c`: Basic executable for testing

To test the sensor:

1. Build the test programs:
   ```bash
   gcc -o fileless testing\ samples/fileless.c
   gcc -o injector testing\ samples/injector.c
   gcc -o sample testing\ samples/sample.c
   ```

2. Run a test container:
   ```bash
   docker run -d --name test_container ubuntu:latest sleep 3600
   ```

3. Start the sensor:
   ```bash
   sudo python3 sensor.py -c test_container
   ```

4. In another terminal, execute the test programs inside the container:
   ```bash
   docker exec -it test_container /path/to/fileless
   ```

Observe the sensor detecting and logging the activities.

## Architecture

The sensor consists of:

1. **eBPF Program**: Kernel-space code that attaches to tracepoints and kprobes
2. **Python User-Space**: Handles event processing, logging, and artifact extraction
3. **Cgroup Tracking**: Isolates monitoring to specific container processes
4. **Ring Buffer**: Efficient data transfer between kernel and user space

Package layout:

- `sensor.py`: Backward-compatible wrapper
- `kernel_flight_recorder/cli.py`: CLI startup and BPF loading
- `kernel_flight_recorder/bpf_program.py`: Embedded eBPF C program
- `kernel_flight_recorder/events.py`: ctypes event structs and JSON event handling
- `kernel_flight_recorder/cgroup.py`: Docker cgroup resolver
- `kernel_flight_recorder/logging_utils.py`: JSON log emission

## Security Considerations

- Requires root privileges for eBPF operations
- Only monitors specified containers to minimize performance impact
- Extracts artifacts for forensic analysis but does not prevent attacks
- Designed for detection and logging, not prevention

## Troubleshooting

### Common Issues

1. **BCC Installation Errors**:
   - Ensure kernel headers match your running kernel
   - Check if eBPF is enabled in your kernel configuration

2. **Container Not Found**:
   - Verify the container is running
   - Use `docker ps` to confirm container status

3. **Permission Denied**:
   - Run with `sudo`
   - Ensure user has access to `/sys/fs/cgroup/`

4. **No Events Detected**:
   - Check if the container has active processes
   - Verify cgroup ID resolution

### Logs

Check `ebpf_sensor.log` for detailed error messages and event logs.
