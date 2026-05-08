"""Docker cgroup resolution."""

import os
import subprocess
import sys


def get_cgroup_id(container_name_or_id):
    try:
        full_id = subprocess.check_output(
            ["docker", "inspect", "--format", "{{.Id}}", container_name_or_id],
            stderr=subprocess.STDOUT,
        ).decode().strip()

        cgroup_path = f"/sys/fs/cgroup/system.slice/docker-{full_id}.scope"
        if not os.path.exists(cgroup_path):
            cgroup_path = f"/sys/fs/cgroup/docker/{full_id}"

        if not os.path.exists(cgroup_path):
            raise FileNotFoundError(
                f"Could not find cgroup directory for {full_id}. Is the container running?"
            )

        cgroup_id = os.stat(cgroup_path).st_ino
        print(
            f"[*] Resolved Container '{container_name_or_id}' -> "
            f"Full ID: {full_id[:12]}... -> Cgroup ID: {cgroup_id}"
        )
        return cgroup_id

    except subprocess.CalledProcessError:
        print(f"[!] Docker error: Container '{container_name_or_id}' not found.")
        sys.exit(1)
    except Exception as e:
        print(f"[!] Cgroup resolution failed: {e}")
        sys.exit(1)
