#ifndef __AP_H__
#define __AP_H__

struct ap_info {
    uint8_t bssid[6];
#define MAX_IE_ELEMENT_SIZE 256
    uint8_t essid[MAX_IE_ELEMENT_SIZE];
#define CRYPT_TYPE_OPEN 0
#define CRYPT_TYPE_WEP 1
#define CRYPT_TYPE_WPA 2
#define CRYPT_TYPE_WPA_MGT 3
    int crypt_type;

    uint16_t last_seq;
    struct ap_info *next;
};

struct wpa_info{
    uint8_t stmac[6];
    uint8_t snonce[32];
    uint8_t anonce[32];
    uint8_t keymic[16];
    uint8_t eapol[256];
    int eapol_size;
#define EAPOL_VERSION_CCMP  2
#define EAPOL_VERSION_TKIP  1
    int keyver;
#define EAPOL_STATE_COMPLETE    7
    int state;
#define WEP_HEADER_LEN 4
#define WPA_HEADER_LEN 8
};

struct sta_info {
    struct ap_info *ap;
    uint8_t sta_mac[6];
    uint8_t qos_flag;
    uint8_t qos_header[2];
    struct wpa_info wpa;
    uint16_t last_seq;
#define PM_SLEEP 1
#define PM_UP 0
    int pm;
    struct sta_info *next;
};

int ap_add (struct ctx *, const uint8_t *, const char *, int);
struct ap_info *ap_lookup (struct ctx *, const uint8_t *);
struct sta_info *sta_lookup (struct ctx *, const uint8_t *);
struct sta_info * sta_add (struct ctx *, const uint8_t *);
#endif
