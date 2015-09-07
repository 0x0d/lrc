#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "ap.h"
#include "logger.h"

struct ap_info *ap_lookup(struct ctx *ctx, const u_char *bssid)
{
    struct ap_info *ap_cur = ctx->ap_list;
    while (ap_cur != NULL) {
        if (!memcmp (ap_cur->bssid, bssid, 6)) {
            break;
        }
        ap_cur = ap_cur->next;
    }
    return ap_cur;
}


int ap_add (struct ctx *ctx, const u_char *bssid, const char *essid, int crypt_type, int channel)
{

    struct ap_info *ap_cur;

    if (ap_lookup (ctx, bssid)) { // ap already exist
        return 0;
    }

    logger(INFO, "Adding new AP [%02X:%02X:%02X:%02X:%02X:%02X] %s Crypt: %d Channel: %d", bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5], essid, crypt_type, channel);

    ap_cur = (struct ap_info *) malloc (sizeof (struct ap_info));
    if (!ap_cur) {
        logger(WARN, "ap_add: malloc failed");
        return 0;
    }

    memset (ap_cur, 0, sizeof (struct ap_info));
    memcpy (ap_cur->bssid, bssid, 6);
    strcpy ((char *) ap_cur->essid, essid);
    ap_cur->crypt_type = crypt_type;

    ap_cur->next = ctx->ap_list;
    ctx->ap_list = ap_cur;

    return 1;
}

void ap_list_destroy (struct ctx *ctx)
{
    struct ap_info *ap_cur, *ap_next;
    ap_cur = ctx->ap_list;

    while (ap_cur) {
        ap_next = ap_cur->next;
        free (ap_cur);
        ap_cur = ap_next;
    }
}


struct sta_info *sta_lookup (struct ctx *ctx, const u_char *sta_mac)
{
    struct sta_info *sta_cur = ctx->sta_list;
    while (sta_cur != NULL) {
        if (!memcmp (sta_cur->sta_mac, sta_mac, 6)) {
            break;
        }
        sta_cur = sta_cur->next;
    }
    return sta_cur;
}


struct sta_info * sta_add (struct ctx *ctx, const u_char *sta_mac)
{
    struct sta_info *sta_cur;
    logger(INFO, "Adding new STA [%02X:%02X:%02X:%02X:%02X:%02X]", sta_mac[0], sta_mac[1], sta_mac[2], sta_mac[3], sta_mac[4], sta_mac[5]);
    sta_cur = (struct sta_info *) malloc (sizeof (struct sta_info));
    if (!sta_cur) {
        logger(WARN, "sta_add: malloc failed");
        return NULL;
    }

    memset (sta_cur, 0, sizeof(struct sta_info));
    memcpy (sta_cur->sta_mac, sta_mac, 6);
    sta_cur->qos_flag = 0;
    sta_cur->next = ctx->sta_list;
    ctx->sta_list = sta_cur;
    return sta_cur;
}


void sta_list_destroy (struct ctx *ctx)
{
    struct sta_info *sta_cur, *sta_next;
    sta_cur = ctx->sta_list;

    while (sta_cur) {
        sta_next = sta_cur->next;
        free (sta_cur);
        sta_cur = sta_next;
    }
}

