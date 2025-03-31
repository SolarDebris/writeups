#ifndef _H_LOG

#define _H_LOG

#define LOG(format, ...) \
    printf("[*] [%s] %s - %d:", __FILE__, __func__, __LINE__); \
    printf(format, ##__VA_ARGS__); \
    printf("\n"); 

