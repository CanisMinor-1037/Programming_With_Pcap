/**
 * @file simple_sniffer.c
 * @author seed  
 * 
 * @brief a simple sniffer
 * @version 0.1
 * @date 2022-07-07
 * 
 * @copyright Copyright (c) 2022
 * 
 */
#include <pcap.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#define MAXBYTE2CAPTURE 2048

void processPacket(u_char *arg, const struct pcap_pkthdr * pkthdr, const u_char * packet) {
    int i = 0, *counter = (int *)arg;
    printf("Got a Packet\n");
    printf("Packet Count: %d\n", ++(*counter));
    printf("Received Packet Size: %d\n", pkthdr->len);
    printf("Payload:\n");
    for (i = 0; i < pkthdr->len; i++) {
        if (isprint(packet[i])) { // 可打印字符
            printf("%c ", packet[i]);
        } else {
            printf(". ");
        }

        if (((i % 16) == 0 && i != 0) || i == pkthdr->len - 1) {
            printf("\n");
        }
    }

    return;
}

int main(void) {
    int i = 0, count = 0;
    pcap_t * descr = NULL;
    char errbuf[PCAP_ERRBUF_SIZE], *device = NULL;
    memset(errbuf, 0, PCAP_ERRBUF_SIZE);

    /* Get the name of the first device suitable for capture */
    if ((device = pcap_lookupdev(errbuf)) == NULL) {
        fprintf(stderr, "pcap_loopupdev error: %s\n", errbuf);
        return 2;
    }

    /* Open device in promoscous mode */    
    printf("Opening device %s\n", device);
    if ((descr = pcap_open_live(device, MAXBYTE2CAPTURE, 1, 1000, errbuf)) == NULL) {
        fprintf(stderr, "pcap_open_live error: %s\n", errbuf);
        return 2;
    }

    /* Loop forever & call processPacket() for every receiced packet */
    if (pcap_loop(descr, -1, processPacket, (u_char *)&count) == -1) {
        fprintf(stderr, "pcap_loop error: %s\n", pcap_geterr(descr));
        return 2;
    }

    return 0;
}