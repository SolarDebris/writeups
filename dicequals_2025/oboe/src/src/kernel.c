#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <stdlib.h>
#include <stropts.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <stdint.h>

#include "kernel.h"

#define PAGE_SIZE 0x1000
#define TTY_STRUCT_SIZE 0x2E0
#define CRED_STRUCT_SIZE 0xA8



