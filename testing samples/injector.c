#define _GNU_SOURCE

#include <stdio.h>
#include <unistd.h>
#include <sys/uio.h>
#include <sys/mman.h>
#include <string.h>
#include <stdlib.h>
#include <sys/wait.h>


unsigned char payload[] = "HELLO_FROM_PARENT";


int main()
{
    sleep(10);
    int pipefd[2];

    if (pipe(pipefd) == -1)
    {
        perror("pipe");
        return 1;
    }

    pid_t child = fork();

    if (child == 0)
    {
        close(pipefd[0]);  // close read end

        void *mem = mmap(
            NULL,
            4096,
            PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS,
            -1,
            0
        );

        if (mem == MAP_FAILED)
        {
            perror("mmap");
            exit(1);
        }

        printf("[+] Child allocated memory at %p\n", mem);

        /* send address to parent */

        write(pipefd[1], &mem, sizeof(mem));

        sleep(6);

        printf("[+] Child memory now contains: %s\n", (char *)mem);

        return 0;
    }

    else
    {
        close(pipefd[1]);  // close write end

        void *remote_addr;

        read(pipefd[0], &remote_addr, sizeof(remote_addr));

        printf("[+] Parent received child address %p\n", remote_addr);

        sleep(2);

        struct iovec local[1];
        struct iovec remote[1];

        local[0].iov_base = payload;
        local[0].iov_len = sizeof(payload);

        remote[0].iov_base = remote_addr;
        remote[0].iov_len = sizeof(payload);

        ssize_t bytes = process_vm_writev(
            child,
            local,
            1,
            remote,
            1,
            0
        );

        if (bytes == -1)
        {
            perror("process_vm_writev");
        }
        else
        {
            printf("[+] Injected %ld bytes\n", bytes);
        }
        
        wait(NULL);
    }

    return 0;
}