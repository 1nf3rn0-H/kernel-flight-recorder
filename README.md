# eBPF Threat Hunter Sensor

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
   git clone <repository-url>
   cd ebpf-sensor
   ```

## Usage

Run the sensor targeting a specific Docker container:

```bash
sudo python3 sensor.py -c <container_name_or_id>
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

## Sample Testing Output
```json
[*] Resolved Container 'detonation_zone' -> Full ID: 5ef6c847ee77... -> Cgroup ID: 16774
[*] Compiling eBPF and tracing Cgroup ID 16774...
[*] Ring Buffer Active. Hunting threats inside the container...
{"timestamp": "2026-04-21T17:48:04.685800+00:00", "sensor_type": "ebpf_threat_hunter", "event_type": "EXECVE", "actor": {"pid": 15938, "process_name": "bash"}, "details": {"true_path": "./injector", "first_arg": ""}}
{"timestamp": "2026-04-21T17:48:16.694266+00:00", "sensor_type": "ebpf_threat_hunter", "event_type": "PROCESS_VM_WRITEV", "actor": {"pid": 15938, "process_name": "injector"}, "target": {"pid": 31, "memory_address": "0xf4663415b000"}, "payload": {"bytes_injected": 18, "status": "extracted_from_source", "artifact_path": "/home/harsh/Desktop/Project/success/dump_injector_15938_0xaf3a4c7a0010.bin", "sha256": "32a15e53d9691dd2085e17c16d6eb66fbd344f30cf071ff3b39543c85d775f04"}}
{"timestamp": "2026-04-21T17:48:35.971870+00:00", "sensor_type": "ebpf_threat_hunter", "event_type": "EXECVE", "actor": {"pid": 15990, "process_name": "bash"}, "details": {"true_path": "./fileless", "first_arg": ""}}
{"timestamp": "2026-04-21T17:48:35.975324+00:00", "sensor_type": "ebpf_threat_hunter", "event_type": "MEMFD_CREATE", "actor": {"pid": 15990, "process_name": "fileless"}, "details": {"anonymous_file_name": "kthread_worker"}}
{"timestamp": "2026-04-21T17:48:36.975077+00:00", "sensor_type": "ebpf_threat_hunter", "event_type": "EXECVE", "actor": {"pid": 15990, "process_name": "fileless"}, "details": {"true_path": "/proc/self/fd/3", "first_arg": ""}, "fileless_payload": {"status": "extracted", "artifact_path": "/home/harsh/Desktop/Project/success/dump_memfd_15990_fd3.bin", "sha256": "63da86ffdb115a56ccdc545f2eeadfded2ba2e2a13994f3ad89b264945d53bb2", "preview": "#!/bin/bash\necho '[!!!] Fileless payload executing"}}
^C
[*] Exiting...
```

## Architecture

The sensor consists of:

1. **eBPF Program**: Kernel-space code that attaches to tracepoints and kprobes
2. **Python User-Space**: Handles event processing, logging, and artifact extraction
3. **Cgroup Tracking**: Isolates monitoring to specific container processes
4. **Ring Buffer**: Efficient data transfer between kernel and user space

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

## Disclaimer

This tool is for security research and monitoring purposes. Use responsibly and in compliance with applicable laws and regulations.