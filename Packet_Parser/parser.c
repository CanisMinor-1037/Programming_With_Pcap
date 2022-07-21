/**
 * @file parser.c
 * @author seed 
 * @brief read the pcap-savefile and parse the packet
 * @version 0.2
 * @date 2022-07-17
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
#include <netinet/if_ether.h>

#define IP_HDR_LEN 20
#define UDP_HDR_LEN 8
#define TCP_HDR_LEN_MIN 20

#define ARP_REQUEST 1 /* ARP Request */
#define ARP_REPLY 2 /* ARP Reply */

int main(int argc, char *argv[]) {
    pcap_t * handle = NULL; /* Session Handle */
    char errbuf[PCAP_ERRBUF_SIZE]; /* Error Buffer */
    struct pcap_pkthdr pkthdr; /* Packet Infomation */
    const u_char * packet = NULL; /* Received Raw Data */
    struct ether_header * etherh; /* Ether Header */
    struct ether_arp * arp; /* Ethernet Address Resolution Protocol */
    struct iphdr * iph; /* IP Header */
    struct tcphdr * tcph; /* TCP Header */
    struct udphdr * udph; /* UDP Header */
    int t_payload_offset = 0; /* Offset of Payload of Transport Layer */
    int len; /* Packet Length */

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
        printf("Received Packet Size: %d\n", pkthdr.len); len = pkthdr.len;

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
        if (ntohs(etherh->ether_type) == ETHERTYPE_IP) {
            printf("Network Layer[IP]:\n");
            iph = (struct iphdr *)(packet + 14); /* Assuming is Ethernet */ 
            printf("\tVer.: 0x%01x\n", iph->version);
            printf("\tTHL: 0x%01x\n", iph->ihl);
            printf("\tType of Service: 0x%02x\n", ntohs(iph->tos));
            printf("\tTotal length: %u\n", ntohs(iph->tot_len));
            printf("\tIdentification: 0x%04x\n", ntohs(iph->id));
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
                t_payload_offset = ETHER_HDR_LEN + IP_HDR_LEN + UDP_HDR_LEN;
            } else if (iph->protocol == IPPROTO_TCP) {
                printf("Transport Layer[TCP]:\n");
                tcph = (void *)iph + iph->ihl * 4;
                printf("\tSource Port: %u\n", ntohs(tcph->source));
                printf("\tDestination Port: %u\n", ntohs(tcph->dest));
                printf("\tSequence Number: %u\n", ntohl(tcph->seq));
                printf("\tAcknowledgement Number: %u\n", ntohl(tcph->ack_seq));
                printf("\tData Offset: %u\n", tcph->doff);
                printf("\tFLAGS:\tURG ACK PSH RST SYN FIN\n");
                printf("\t      \t%-4x%-4x%-4x%-4x%-4x%-4x\n", tcph->urg, tcph->ack, tcph->psh, tcph->rst, tcph->syn, tcph->fin);
                printf("\tAdvertised Window: %u\n", ntohs(tcph->window));
                printf("\tChecksum: 0x%04x\n", ntohs(tcph->check));
                printf("\tUrgent Offset: %u\n", ntohs(tcph->urg_ptr));
                t_payload_offset = ETHER_HDR_LEN + IP_HDR_LEN + tcph->doff * 4;
                if (tcph->doff > 5) { /* Options and Padding */
                    printf("\tOptions and Padding:\n\t\t");
                    for (int i = ETHER_HDR_LEN + IP_HDR_LEN + TCP_HDR_LEN_MIN; i < len; i++) {
                        printf("%02x ", packet[i]);

                        if (((i % 16) == 0 && i != 0) || i == len - 1) {
                            printf("\n\t\t");
                        }
                    }
                }
            } else {
                continue;
            }
            /* Application Layer */
            if (t_payload_offset < len) {
                printf("Application Layer:\n\t");
            }
            for (int i = t_payload_offset; i < len; i++) {
                if (isprint(packet[i])) { // 可打印字符
                    printf("%c ", packet[i]);
                } else {
                    printf(". ");
                }

                if (((i % 16) == 0 && i != 0) || i == len - 1) {
                    printf("\n\t");
                }
            }
        } else if (ntohs(etherh->ether_type) == ETHERTYPE_ARP) {
            printf("ARP:\n");
            arp = (struct ether_arp *)(packet + 14); /* Assuming is Ethernet */ 
            printf("\tReceived Packet Size: %d bytes\n", pkthdr.len);
            printf("\tHardware type: %s\n", (ntohs(arp->ea_hdr.ar_hrd) == 1) ? "Ethernet" : "Unknown");
            printf("\tProtocol Type: %s\n", (ntohs(arp->ea_hdr.ar_pro) == 0x0800) ? "IPv4" : "Unknown");
            printf("\tHardware Size: %u\n", arp->ea_hdr.ar_hln);
            printf("\tProtocol Size: %u\n", arp->ea_hdr.ar_pln);
            printf("\tOperation: %s\n", (ntohs(arp->ea_hdr.ar_op) == ARP_REQUEST) ? "ARP Request" : "ARP Reply");

            if (ntohs(arp->ea_hdr.ar_hrd) == 1 && ntohs(arp->ea_hdr.ar_pro) == 0x0800) {
                printf("\tSender MAC: ");
                for (int i = 0; i < 6; i++) {
                    printf("%02X:", arp->arp_sha[i]);
                }
                printf("\n\tSender IP: ");
                for (int i = 0; i < 4; i++) {
                    printf("%d.", arp->arp_spa[i]);
                }
                printf("\n\tTarget MAC: ");
                for (int i = 0; i < 6; i++) {
                    printf("%02X:", arp->arp_tha[i]);
                }
                printf("\n\tTarget IP: ");
                for (int i = 0; i < 4; i++) {
                    printf("%d.", arp->arp_tpa[i]);
                }
                printf("\n");
            }
        } else {
            continue;
        }
    }
    if (packet == NULL) {
        fprintf(stderr, "pcap_next error: %s\n", pcap_geterr(handle));
        exit(1);
    }
    return 0;
}