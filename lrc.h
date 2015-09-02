#ifndef __LRC_H__
#define __LRC_H__

#include <libnet.h>
#include <pcap.h>
#include <pthread.h>

#define PLATFORM_LINUX 1

#include "osdep/osdep.h"
#include "ieee80211.h"

#define HOP_DEFAULT_TIMEOUT 5
#define MTU 1400

// Can`t be > 4096
#define MAX_PACKET_LENGTH 4096
#define ALRM_TIME 5

// context for holding program state
struct ctx {
    char *if_inj_name;
    char *if_mon_name;

    u_char if_inj_mac[6];
    u_char if_mon_mac[6];

    u_int channels[14];
    u_int channel_fix;

    libnet_t *lnet;
    libnet_ptag_t lnet_p_tcp;
    libnet_ptag_t lnet_p_udp;
    libnet_ptag_t lnet_p_ip;

    u_int mtu; 

    pthread_mutex_t mutex;

    struct matcher_entry *matchers_list;
    u_int hop_time;

    // OSDEP structs
    struct wif *wi_inj;
    struct wif *wi_mon;

    struct ap_info *ap_list;
    struct sta_info *sta_list;

};
#endif
