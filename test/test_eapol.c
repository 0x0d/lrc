/*
 *
 * test-calc-ptk.c
 *
 * Copyright (C) 2012 Carlos Alberto Lopez Perez <clopez@igalia.com>
 *
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 * MA 02110-1301, USA.
 *
 */


#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <string.h>
#include "../crypto.h"
#include "../ap.h"

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


    static unsigned char pkt1[99] = "\x01\x03\x00\x5f\x02\x00\x8a\x00\x10\x00\x00\x00\x00\x00\x00\x00\x01\x22\x58\x54\xb0\x44\x4d\xe3\xaf\x06\xd1\x49\x2b\x85\x29\x84\xf0\x4c\xf6\x27\x4c\x0e\x32\x18\xb8\x68\x17\x56\x86\x4d\xb7\xa0\x55\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
    static unsigned char pkt2[121] = "\x01\x03\x00\x75\x02\x01\x0a\x00\x10\x00\x00\x00\x00\x00\x00\x00\x01\x59\x16\x8b\xc3\xa5\xdf\x18\xd7\x1e\xfb\x64\x23\xf3\x40\x08\x8d\xab\x9e\x1b\xa2\xbb\xc5\x86\x59\xe0\x7b\x37\x64\xb0\xde\x85\x70\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xd5\x35\x53\x82\xb8\xa9\xb8\x06\xdc\xaf\x99\xcd\xaf\x56\x4e\xb6\x00\x16\x30\x14\x01\x00\x00\x0f\xac\x04\x01\x00\x00\x0f\xac\x04\x01\x00\x00\x0f\xac\x02\x01\x00";
    static unsigned char pkt3[155] = "\x01\x03\x00\x97\x02\x13\xca\x00\x10\x00\x00\x00\x00\x00\x00\x00\x02\x22\x58\x54\xb0\x44\x4d\xe3\xaf\x06\xd1\x49\x2b\x85\x29\x84\xf0\x4c\xf6\x27\x4c\x0e\x32\x18\xb8\x68\x17\x56\x86\x4d\xb7\xa0\x55\x19\x2e\xee\xf7\xfd\x96\x8e\xc8\x0a\xee\x3d\xfb\x87\x5e\x82\x22\x37\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x1e\x22\x86\x72\xd2\xde\xe9\x30\x71\x4f\x68\x8c\x57\x46\x02\x8d\x00\x38\x3c\xa9\x18\x54\x62\xec\xa4\xab\x7f\xf5\x1c\xd3\xa3\xe6\x17\x9a\x83\x91\xf5\xad\x82\x4c\x9e\x09\x76\x37\x94\xc6\x80\x90\x2a\xd3\xbf\x07\x03\x45\x2f\xbb\x7c\x1f\x5f\x1e\xe9\xf5\xbb\xd3\x88\xae\x55\x9e\x78\xd2\x7e\x6b\x12\x1f";
    static unsigned char pkt4[99] = "\x01\x03\x00\x5f\x02\x03\x0a\x00\x10\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x9d\xc8\x1c\xa6\xc4\xc7\x29\x64\x8d\xe7\xf0\x0b\x43\x63\x35\xc8\x00\x00";

    static unsigned char ostmac[6] = "\x00\x13\x46\xfe\x32\x0c";
    static unsigned char obssid[6] = "\x00\x14\x6c\x7e\x40\x80";
    static char essid[9] = "Harkonen\x00";
    static char key[8] = "\x31\x32\x33\x34\x35\x36\x37\x38";

    unsigned char pmk[40];
    unsigned char ptk[80];    

    struct sta_info *sta;
    sta = (struct sta_info *) malloc(sizeof(struct sta_info));
    struct ap_info *ap;
    ap = (struct ap_info *) malloc(sizeof(struct ap_info));

    bzero(sta,sizeof(struct sta_info));
    bzero(ap,sizeof(struct ap_info));
    
    sta->ap = ap;    

    printf("essid: %s\n", essid);
    calc_pmk(key, essid, pmk);
    hexdump(pmk, 40);

    memcpy(sta->wpa.stmac, ostmac, 6);
    memcpy(sta->ap->bssid, obssid, 6);
    eapol_wpa_process(pkt1, 99, sta);
    eapol_wpa_process(pkt2, 121, sta);
    eapol_wpa_process(pkt3, 155, sta);
    eapol_wpa_process(pkt4, 99, sta);
   
    printf("stmac------------\n");
    hexdump(sta->wpa.stmac, 6);
    printf("anonce------------\n");
    hexdump(sta->wpa.anonce, 32); 
    printf("eapol------------\n");
    hexdump(sta->wpa.eapol, 256);
    printf("keymic------------\n");
    hexdump(sta->wpa.keymic, 16); 
    printf("snonce------------\n");
    hexdump(sta->wpa.snonce, 32); 
    printf("eapol_size------------\n");
    printf("%d\n", sta->wpa.eapol_size);
    printf("------------\n");

 //  unsigned char pmk[32];  // ???????????????

    if(calc_ptk(sta, pmk)) {
        printf("OK\n");
    } else {
        printf("FALSE\n");
    }   



}

