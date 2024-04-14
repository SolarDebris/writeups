#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/user.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>


int main(void) {

    void *res;
    pid_t child = 3784;

    int *flag = 0x404050;
    int *flag2 = 0x404051;
    int *flag3 = 0x404052;
    int *flag4 = 0x404053;
    int *flag5 = 0x404054;
    int err = ptrace(PTRACE_ATTACH, child, NULL, NULL);
    printf("Error code: %d\n", errno);

    err = ptrace(PTRACE_PEEKDATA, child, flag, res);
    printf("Error code: %d\n %s", errno, res);

    err = ptrace(PTRACE_PEEKDATA, child, flag2, res);
    printf("Error code: %d\n %s", errno, res);
    
    err = ptrace(PTRACE_PEEKDATA, child, flag3, res);
    printf("Error code: %d\n %s", errno, res);
    
    err = ptrace(PTRACE_PEEKDATA, child, flag4, res);
    printf("Error code: %d\n %s", errno, res);

    err = ptrace(PTRACE_PEEKDATA, child, flag5, res);
    printf("Error code: %d\n %s", errno, res);

    int fd = open("/proc/132427/cmdline", 0);

    if (fd == -1) {
        perror("Error opening file");
        exit(EXIT_FAILURE);
    }

    char *buf;

    read(fd, buf, 0x10);

    printf("%d", fd);


}
