/**
 * @file divide.cpp
 * @author CanisMinor-1037
 * @brief Classifying Network Traffic - C++ Version
 * @version 0.1
 * @date 2022-07-21
 * 
 * @copyright Copyright (c) 2022
 * 
 */
#include <cstdio>
#include <iostream>
#include <map>
#include <string>
#include <pcap.h>
#include <cstring>
#include <cstdlib>
#include <cctype>
#include <climits>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/if_ether.h>
#include <vector>

#define IP_HDR_LEN 20
#define UDP_HDR_LEN 8
#define TCP_HDR_LEN_MIN 20

#define ARP_REQUEST 1 /* ARP Request */
#define ARP_REPLY 2 /* ARP Reply */

#define MAXLEN 50

unsigned int visited[UINT_MAX + 1];
char five_tuple[MAXLEN];
 
// AP Hash Function
unsigned int
APHash(char *str)
{
    unsigned int hash = 0;
    int i;
 
    for (i=0; *str; i++)
    {
        if ((i & 1) == 0)
        {
            hash ^= ((hash << 7) ^ (*str++) ^ (hash >> 3));
        }
        else
        {
            hash ^= (~((hash << 11) ^ (*str++) ^ (hash >> 5)));
        }
    }
 
    return (hash & 0x7FFFFFFF);
}

int
main(int argc, char *argv[]) {
    using namespace std;

    pcap_t * handle = NULL; /* Session Handle */
    char errbuf[PCAP_ERRBUF_SIZE]; /* Error Buffer */
    struct pcap_pkthdr pkthdr; /* Packet Infomation */
    const u_char * packet = NULL; /* Received Raw Data */
    struct ether_header * etherh; /* Ether Header */
    struct ether_arp * arp; /* Ethernet Address Resolution Protocol */
    struct iphdr * iph; /* IP Header */
    struct tcphdr * tcph; /* TCP Header */
    struct udphdr * udph; /* UDP Header */
    int len; /* Packet Length */
    unsigned int count = 0;
    unsigned int aphash; /* APHash */
    
    

    if (argc != 2) {
        fprintf(stderr, "Usage: ./divide <filename>\n");
        exit(1);
    }
    if ((handle = pcap_open_offline(argv[1], errbuf)) == NULL) {
        fprintf(stderr, "pcap_open_offline error: %s\n", errbuf);
        exit(1);
    }

    while ((packet = pcap_next(handle, &pkthdr)) != NULL) {
        len = pkthdr.len;

        /* Data-Link Layer */
        etherh = (struct ether_header *)packet;
        if (ntohs(etherh->ether_type) == ETHERTYPE_IP) {
            printf("Network Layer[IP]:\n");
            iph = (struct iphdr *)(packet + 14); /* Assuming is Ethernet */ 
            printf("\tProtocol: %d\n", iph->protocol);
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
                udph = (udphdr *)((void *)iph + iph->ihl * 4);
                printf("\tSource Port: %u\n", ntohs(udph->source));
                printf("\tDestination Port: %u\n", ntohs(udph->dest));
                if (udph->source >= udph->dest) {
                    sprintf(five_tuple, "%x%x%x%x%x", iph->saddr, udph->source, iph->daddr, udph->dest, IPPROTO_UDP);
                } else {
                    sprintf(five_tuple, "%x%x%x%x%x", iph->daddr, udph->dest, iph->saddr, udph->source, IPPROTO_UDP);
                }
                cout << five_tuple << endl;
                aphash = APHash(five_tuple);
                /* write the packet into test<visited[aphash]>.pcap */
                if (visited[aphash] == 0) {
                    /* not visited */
                    visited[aphash] = count++;
                    
                } else {

                }

                
                
            } else if (iph->protocol == IPPROTO_TCP) {
                printf("Transport Layer[TCP]:\n");
                tcph = (tcphdr *)((void *)iph + iph->ihl * 4);
                printf("\tSource Port: %u\n", ntohs(tcph->source));
                printf("\tDestination Port: %u\n", ntohs(tcph->dest));
                if (udph->source >= udph->dest) {
                    sprintf(five_tuple, "%x%x%x%x%x", iph->saddr, udph->source, iph->daddr, udph->dest, IPPROTO_TCP);
                } else {
                    sprintf(five_tuple, "%x%x%x%x%x", iph->daddr, udph->dest, iph->saddr, udph->source, IPPROTO_TCP);
                }
                cout << five_tuple << endl;
                /* write the packet into test<visited[aphash]>.pcap */
                if (visited[aphash] == 0) {
                    /* not visited */
                    visited[aphash] = count++;
                    
                } else {
                    
                }
            } else {
                continue;
            }
        }
    }
    if (packet == NULL) {
        fprintf(stderr, "pcap_next error: %s\n", pcap_geterr(handle));
        exit(1);
    }
    return 0;
}