#ifndef __AP_H__
#define __AP_H__

#include "lrc.h"

struct ap_info {
    u_char bssid[6];
#define MAX_IE_ELEMENT_SIZE 256
    u_char essid[MAX_IE_ELEMENT_SIZE];
#define CRYPT_TYPE_OPEN 0
#define CRYPT_TYPE_WEP 1
#define CRYPT_TYPE_WPA 2
#define CRYPT_TYPE_WPA_MGT 3
    int crypt_type;
    int channel;
    char *password;
    u_char pmk[40];
    struct ap_info *next;
};

struct wpa_info {
    u_char stmac[6];
    u_char snonce[32];
    u_char anonce[32];
    u_char keymic[16];
    u_char eapol[256];
    u_char ptk[80];
    int eapol_size;
#define EAPOL_VERSION_CCMP  2
#define EAPOL_VERSION_TKIP  1
    int keyver;
#define EAPOL_STATE_PROCESSING 10
#define EAPOL_STATE_CAN_RENEW 0
#define EAPOL_STATE_COMPLETE 7
    int state;
};

struct sta_info {
    struct ap_info *ap;
    u_char sta_mac[6];
    u_char qos_flag;
    u_char qos_header[2];
    struct wpa_info wpa;
    struct sta_info *next;
};

int ap_add (struct ctx *, const u_char *, const char *, int, int);
struct ap_info *ap_lookup (struct ctx *, const u_char *);
struct sta_info *sta_lookup (struct ctx *, const u_char *);
struct sta_info * sta_add (struct ctx *, const u_char *);

#endif
