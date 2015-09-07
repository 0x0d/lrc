/*
 *  MD5, SHA-1, RC4 and AES implementations
 *
 *  Copyright (C) 2001-2004  Christophe Devine
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#ifndef _CRYPTO_H
#define _CRYPTO_H

#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <openssl/rc4.h>
#include <openssl/aes.h>
#include <stdint.h>

#include "lrc.h"
#include "ap.h"

#define S_LLC_SNAP      "\xAA\xAA\x03\x00\x00\x00"
#define S_LLC_SNAP_ARP  (S_LLC_SNAP "\x08\x06")
#define S_LLC_SNAP_IP   (S_LLC_SNAP "\x08\x00")
#define S_LLC_SNAP_SPANTREE   "\x42\x42\x03\x00\x00\x00\x00\x00"
#define S_LLC_SNAP_CDP  "\xAA\xAA\x03\x00\x00\x0C\x20"
#define IEEE80211_FC1_DIR_FROMDS                0x02

#define TYPE_ARP    0
#define TYPE_IP     1
#define	IEEE80211_FC0_SUBTYPE_MASK              0xf0
#define	IEEE80211_FC0_SUBTYPE_SHIFT             4

#define	IEEE80211_FC0_SUBTYPE_QOS               0x80
#define	IEEE80211_FC0_SUBTYPE_QOS_NULL          0xc0

#define GET_SUBTYPE(fc) \
    ( ( (fc) & IEEE80211_FC0_SUBTYPE_MASK ) >> IEEE80211_FC0_SUBTYPE_SHIFT ) \
        << IEEE80211_FC0_SUBTYPE_SHIFT


#define NULL_MAC  (u_char*)"\x00\x00\x00\x00\x00\x00"
#define SPANTREE  (u_char*)"\x01\x80\xC2\x00\x00\x00"
#define CDP_VTP   (u_char*)"\x01\x00\x0C\xCC\xCC\xCC"

#define ROL32( A, n ) \
	( ((A) << (n)) | ( ((A)>>(32-(n))) & ( (1UL << (n)) - 1 ) ) )
#define ROR32( A, n ) ROL32( (A), 32-(n) )

#define EAPOL_PAIRWISE                0x08
#define EAPOL_INSTALL                 0x40
#define EAPOL_ACK                     0x80
#define EAPOL_MIC                     0x01

#define EAPOL_KEY_VERSION   7

#define ZERO "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"

struct WPA_ST_info {
    struct WPA_ST_info *next;	/* next supplicant              */
    u_char stmac[6];		/* supplicant MAC               */
    u_char bssid[6];		/* authenticator MAC            */
    u_char snonce[32];	/* supplicant nonce             */
    u_char anonce[32];	/* authenticator nonce          */
    u_char keymic[20];	/* eapol frame MIC              */
    u_char eapol[256];	/* eapol frame contents         */
    u_char ptk[80];		/* pairwise transcient key      */
    int eapol_size;		/* eapol frame size             */
    u_long t_crc;	/* last ToDS   frame CRC        */
    u_long f_crc;	/* last FromDS frame CRC        */
    int keyver, valid_ptk;
};

struct Michael {
    u_long key0;
    u_long key1;
    u_long left;
    u_long right;
    u_long nBytesInM;
    u_long message;
    u_char mic[8];
};

struct rc4_state {
    int x, y, m[256];
};

void calc_pmk(char *key, char *essid, u_char pmk[40]);
int check_crc_buf(u_char *buf, int len);
int calc_crc_buf(u_char *buf, int len);
u_long calc_crc(u_char *buf, int len);
u_long calc_crc_plain(u_char *buf, int len);
int add_crc32(u_char *data, int length);
int add_crc32_plain(u_char *data, int length);
int calc_tkip_ppk(u_char *h80211, int caplen, u_char TK1[16],
                  u_char key[16]);
int calc_tkip_mic(u_char * packet, int length, u_char ptk[80], u_char value[8]);
int michael_test(u_char key[8], u_char * message, int length, u_char out[8]);
int calc_tkip_mic_key(u_char * packet, int length, u_char key[8]);

int decrypt_tkip(u_char *h80211, int caplen, u_char TK1[16]);
int decrypt_ccmp(u_char *h80211, int caplen, u_char TK1[16]);
int encrypt_ccmp(u_char *h80211, int caplen, u_char TK1[16]);

/*
int decrypt_wep(uint8_t * src_dst, int h80211_len, uint8_t * password);
int encrypt_wep(uint8_t * src_dst, int len, const uint8_t * wepkey);

int decrypt_wpa(uint8_t * h80211, int h80211_len, struct wpa_info *wp, uint8_t * password, uint8_t * essid, uint8_t * bssid);
int encrypt_wpa(uint8_t * h80211, int h80211_len, struct wpa_info *wp, uint8_t * password, uint8_t * essid, uint8_t * bssid);
*/
int calc_ptk(struct sta_info *, u_char *);
int check_wpa_password(char *, struct sta_info *);
void eapol_wpa_process(u_char *, int, struct sta_info *);
int decrypt_wpa(u_char *, int, struct sta_info *, char *, u_char *, u_char *);
#endif
