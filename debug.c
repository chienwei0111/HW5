#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>
#include "debug.h"

void print_buffer(const unsigned char *bufer,int lingth){
        for (int i =0; i<lingth; i++){
                printf("%02x ", bufer[i]);
        }

        printf("\n");
}

