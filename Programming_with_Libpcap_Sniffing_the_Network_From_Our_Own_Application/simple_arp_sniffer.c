/**
 * @file simple_arp_sniffer.c
 * @author Luis Martin Garcia
 * Edited by CanisMinor
 * @brief Simple ARP Sniffer 
 * @version 0.1
 * @date 2022-07-08
 * 
 * @copyright Copyright (c) 2022
 * 
 */
#include <pcap.h>
#include <string.h>
#include <stdlib.h>

/**
 * @brief ARP Header assuming Ethernet + IPv4
 * @reference TCP/IP Illustrated, Volume 1: The Protocol, Second Edition, Chapter 4
 */
#define ARP_REQUEST 1 /* ARP Request */
#define ARP_REPLY 2 /* ARP Reply */
typedef struct arphdr {
    u_int16_t htype; /* Hardware Type */
    u_int16_t ptype; /* Protocol Type */
    u_int8_t hlen; /* Hardware Address Length */
    u_int8_t plen; /* Protocol Address Length */
    u_int16_t oper; /* Operation */
    u_int8_t sha[6]; /* Sender Hardware Address */
    u_int8_t spa[4]; /* Sender IP Address */
    u_int8_t tha[6]; /* Target Hardware Address */
    u_int8_t tpa[4]; /* Target IP Address */
} arphdr_t;

#define MAXBYTES2CAPTURE 2048

int main(int argc, char *argv[]) {
    bpf_u_int32 netaddr = 0, mask = 0; /* network address and netmask */
    struct bpf_program filter; /* BPF filter program */
    char errbuf[PCAP_ERRBUF_SIZE]; /* Error Buffer */
    pcap_t *descr = NULL; /* Network Interface Handler */
    struct pcap_pkthdr pkthdr; /* Packet information */
    const unsigned char *packet = NULL; /* Received Raw Data */
    arphdr_t *arpheader = NULL; /* Pointer to the ARP header */

    bzero(errbuf, PCAP_ERRBUF_SIZE);

    if (argc != 2) {
        fprintf(stderr, "usage: ./simple_arp_sniffer <interface>\n");
        exit(1);
    } 

    /* Open network device for packet capture */
    if ((descr = pcap_open_live(argv[1], MAXBYTES2CAPTURE, 1, 1000, errbuf)) == NULL) {
        fprintf(stderr, "pcap_open_live error: %s\n", errbuf);
        exit(1);
    }

    /* Look up info from the capture service */
    if (pcap_lookupnet(argv[1], &netaddr, &mask, errbuf) < 0) {
        fprintf(stderr, "pcap_lookupnet failed: %s\n", errbuf);
        netaddr = 0;
        mask = 0;
    }

    /* Compiles the filter express into a BPF filter program */
    if (pcap_compile(descr, &filter, "arp", 1, mask) < 0) {
        fprintf(stderr, "pcap_compile error: %s\n", pcap_geterr(descr));
        exit(1);
    }

    /* Load the filter program into the packet capture device */
    if (pcap_setfilter(descr, &filter) < 0) {
        fprintf(stderr, "pcap_setfilter error: %s\n", pcap_geterr(descr));
        exit(1);
    }

    while (1) {
        packet = pcap_next(descr, &pkthdr); /* Get one packet */
        arpheader = (arphdr_t *)(packet + 14); /* Point to arp header */
        printf("\n\nReceived Packet Size: %d bytes\n", pkthdr.len);
        printf("Hardware type: %s\n", (ntohs(arpheader->htype) == 1) ? "Ethernet" : "Unknown");
        printf("Protocol Type: %s\n", (ntohs(arpheader->ptype) == 0x0800) ? "IPv4" : "Unknown");
        printf("Operation: %s\n", (ntohs(arpheader->oper) == ARP_REQUEST) ? "ARP Request" : "ARP Reply");

        if (ntohs(arpheader->htype) == 1 && ntohs(arpheader->ptype) == 0x0800) {
            printf("Sender MAC: ");
            for (int i = 0; i < 6; i++) {
                printf("%02X:", arpheader->sha[i]);
            }
            printf("\nSender IP: ");
            for (int i = 0; i < 4; i++) {
                printf("%d.", arpheader->spa[i]);
            }
            printf("\nTarget MAC: ");
            for (int i = 0; i < 6; i++) {
                printf("%02X:", arpheader->tha[i]);
            }
            printf("\nTarget IP: ");
            for (int i = 0; i < 4; i++) {
                printf("%d.", arpheader->tpa[i]);
            }
            printf("\n");
        }
    }
    return 0;
}