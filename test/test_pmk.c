#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "crypto.h"

#define PLEN 40
#define KLEN 14

void hexdump (void *addr, u_int len) {
    u_int i;
    u_char buff[17];
    u_char *pc = addr;

    // Process every byte in the data.
    for (i = 0; i < len; i++) {
        // Multiple of 16 means new line (with line offset).

        if ((i % 16) == 0) {
            // Just don't print ASCII for the zeroth line.
            if (i != 0) {
                printf("  %s\n", buff);
            }
            // Output the offset.
            printf("  %04x ", i);
        }

        // Now the hex code for the specific character.
        printf (" %02x", pc[i]);
        // And store a printable ASCII character for later.
        if ((pc[i] < 0x20) || (pc[i] > 0x7e)) {
            buff[i % 16] = '.';
        } else {
            buff[i % 16] = pc[i];
        }
        buff[(i % 16) + 1] = '\0';
    }

    // Pad out last line if not exactly 16 characters.
    while ((i % 16) != 0) {
        printf ("   ");
        i++;
    }
    // And print the final ASCII bit.
    printf ("  %s\n", buff);
}



int main(int argc, char **argv)
{
    if (argc < 1) return 1;

    static unsigned char expected[PLEN] =
             "\x1d\x4d\xf5\x5d\xd8\xd9\x13\xf5\x54\x0d\x05\x3c\xdb\x57\x83\x53"
             "\xd0\x6c\x0f\xb3\x50\x71\x10\xee\x48\xda\xce\x2b\x60\xf6\xd0\xd4"
             "\xc2\x24\x39\x9f\xe8\x1d\x1e\x80";
    static char key[KLEN] =
             "\x6E\x9C\x7A\x91\x9F\xB8\xAE\x93\xC1\xAB\x80\x3C\x09\x00";
    static char essid[8] = "T3st1ng";


    unsigned char pmk[PLEN]; 

    printf("Calc try\n");
    calc_pmk( key, essid, pmk );
    hexdump(pmk, PLEN);
    printf("-----------------\n");

    printf("Expected\n");
    hexdump(expected, PLEN);
    printf("-----------------\n");


}

