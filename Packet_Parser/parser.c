/**
 * @file parser.c
 * @author seed 
 * @brief read the pcap-savefile and parse the packet
 * @version 0.1
 * @date 2022-07-15
 * 
 * @copyright Copyright (c) 2022
 * 
 */
#include <pcap.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
int main(int argc, char *argv[]) {
    pcap_t * handle = NULL; /* Session Handle */
    char errbuf[PCAP_ERRBUF_SIZE]; /* Error Buffer */
    struct pcap_pkthdr pkthdr; /* Packet Infomation */
    const u_char * packet = NULL; /* Received Raw Data */
    struct ether_header * etherh; /* Ether Header */
    struct iphdr * iph; /* IP Header */
    struct tcphdr * tcph; /* TCP Header */
    struct udphdr * udph; /* UDP Header */
    int count = 0;
    
    if (argc != 2) {
        fprintf(stderr, "Usage: ./read_pcapfile <filename>\n");
        exit(1);
    }
    if ((handle = pcap_open_offline(argv[1], errbuf)) == NULL) {
        fprintf(stderr, "pcap_open_offline error: %s\n", errbuf);
        exit(1);
    }

    while ((packet = pcap_next(handle, &pkthdr)) != NULL) {
        printf("\nPacket[%d]:\n", ++count);
        printf("Received Packet Size: %d\n", pkthdr.len);

        /* Data-Link Layer */
        etherh = (struct ether_header *)packet;
        printf("Data-Link Layer:\n");
        printf("\tDestination: ");
        for (int i = 0; i < 5; i++) {
            printf("%02x:", etherh->ether_dhost[i]);
        }
        printf("%02x\n", etherh->ether_dhost[5]);
        printf("\tSource: ");
        for (int i = 0; i < 5; i++) {
            printf("%02x:", etherh->ether_shost[i]);
        }
        printf("%02x\n", etherh->ether_shost[5]);
        printf("\tType: 0x%04x\n", ntohs(etherh->ether_type));

        /* Network Layer */
        if (ntohs(etherh->ether_type) != ETHERTYPE_IP) {
            continue;
        }
        printf("Network Layer:\n");
        iph = (struct iphdr *)(packet + 14); /* Assuming is Ethernet */ 
        printf("\tVer.: 0x%01x\n", iph->version);
        printf("\tTHL: 0x%01x\n", iph->ihl);
        printf("\tType of Service: 0x%02x\n", ntohs(iph->tos));
        printf("\tTotal length: %u\n", ntohs(iph->tot_len));
        printf("\tIdentification: 0x%04x\n", ntohs(iph->id));
        /* 0x1110 0000 0000 0000 */
        printf("\tFlags: 0x%02x\n", ntohs(0x00e0 & iph->frag_off) >> 13);
        printf("\tFragment offset: 0x%04x\n", ntohs(0xff1f & iph->frag_off));
        printf("\tTime to live: %d\n", iph->ttl);
        printf("\tProtocol: %d\n", iph->protocol);
        printf("\tHeader checksum: 0x%04x\n", ntohs(iph->check));
        printf("\tSource Address: %d.%d.%d.%d\n",
            ((u_char *)&iph->saddr)[0],
            ((u_char *)&iph->saddr)[1],
            ((u_char *)&iph->saddr)[2],
            ((u_char *)&iph->saddr)[3]);
        printf("\tDestination Address: %d.%d.%d.%d\n",
            ((u_char *)&iph->daddr)[0],
            ((u_char *)&iph->daddr)[1],
            ((u_char *)&iph->daddr)[2],
            ((u_char *)&iph->daddr)[3]);
        /* Transport Layer */
        if (iph->protocol == IPPROTO_UDP) {
            printf("Transport Layer[UDP]:\n");
            udph = (void *)iph + iph->ihl * 4;
            printf("\tSource Port: %u\n", ntohs(udph->source));
            printf("\tDestination Port: %u\n", ntohs(udph->dest));
            printf("\tLength: %u\n", ntohs(udph->len));
            printf("\tChecksum: 0x%04x\n", ntohs(udph->check));
        } else if (iph->protocol == IPPROTO_TCP) {
            printf("Transport Layer[TCP]:\n");
            tcph = (void *)iph + iph->ihl * 4;
            printf("\tSource Port: %u\n", ntohs(tcph->source));
            printf("\tDestination Port: %u\n", ntohs(tcph->dest));
            printf("\tSequence Number: %u\n", ntohl(tcph->seq));
            printf("\tAcknowledgement Number: %u\n", ntohl(tcph->ack_seq));
        } else {
            continue;
        }

        /* Application Layer */

    }
    if (packet == NULL) {
        fprintf(stderr, "pcap_next error: %s\n", pcap_geterr(handle));
        exit(1);
    }
    return 0;
}