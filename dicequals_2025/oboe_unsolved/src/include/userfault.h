#ifndef _H_USERFAULT

#define _H_USERFAULT

#include "kernel.h"
#include "util.h"


void register_userfault(void *fault_page,void *handler);

void* userfaultfd_leak_handler(void* arg);
