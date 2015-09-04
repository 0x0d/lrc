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


#define NULL_MAC  (uchar*)"\x00\x00\x00\x00\x00\x00"
#define SPANTREE  (uchar*)"\x01\x80\xC2\x00\x00\x00"
#define CDP_VTP   (uchar*)"\x01\x00\x0C\xCC\xCC\xCC"

#define uchar  unsigned char

#define ROL32( A, n ) \
	( ((A) << (n)) | ( ((A)>>(32-(n))) & ( (1UL << (n)) - 1 ) ) )
#define ROR32( A, n ) ROL32( (A), 32-(n) )

#define EAPOL_PAIRWISE                0x08
#define EAPOL_INSTALL                 0x40    
#define EAPOL_ACK                     0x80
#define EAPOL_MIC                     0x01

#define EAPOL_KEY_VERSION   7

struct WPA_ST_info {
	struct WPA_ST_info *next;	/* next supplicant              */
	uchar stmac[6];		/* supplicant MAC               */
	uchar bssid[6];		/* authenticator MAC            */
	uchar snonce[32];	/* supplicant nonce             */
	uchar anonce[32];	/* authenticator nonce          */
	uchar keymic[20];	/* eapol frame MIC              */
	uchar eapol[256];	/* eapol frame contents         */
	uchar ptk[80];		/* pairwise transcient key      */
	int eapol_size;		/* eapol frame size             */
	unsigned long t_crc;	/* last ToDS   frame CRC        */
	unsigned long f_crc;	/* last FromDS frame CRC        */
	int keyver, valid_ptk;
};

struct Michael {
	unsigned long key0;
	unsigned long key1;
	unsigned long left;
	unsigned long right;
	unsigned long nBytesInM;
	unsigned long message;
	unsigned char mic[8];
};

struct rc4_state {
	int x, y, m[256];
};

void calc_pmk(char *key, char *essid, unsigned char pmk[40]);
int check_crc_buf(unsigned char *buf, int len);
int calc_crc_buf(unsigned char *buf, int len);
unsigned long calc_crc(unsigned char *buf, int len);
unsigned long calc_crc_plain(unsigned char *buf, int len);
int add_crc32(unsigned char *data, int length);
int add_crc32_plain(unsigned char *data, int length);
int calc_tkip_ppk(unsigned char *h80211, int caplen, unsigned char TK1[16],
		  unsigned char key[16]);
int calc_tkip_mic(uchar * packet, int length, uchar ptk[80], uchar value[8]);
int michael_test(uchar key[8], uchar * message, int length, uchar out[8]);
int calc_tkip_mic_key(uchar * packet, int length, uchar key[8]);

int decrypt_tkip(unsigned char *h80211, int caplen, unsigned char TK1[16]);
int decrypt_ccmp(unsigned char *h80211, int caplen, unsigned char TK1[16]);
int encrypt_ccmp(unsigned char *h80211, int caplen, unsigned char TK1[16]);

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
