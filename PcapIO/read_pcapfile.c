/**
 * @file read_pcapfile.c
 * @author seed 
 * @brief read the pcap-savefile and print out the information
 * @version 0.1
 * @date 2022-07-08
 * 
 * @copyright Copyright (c) 2022
 * 
 */
#include <pcap.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
int main(int argc, char *argv[]) {
    pcap_t * handle = NULL; /* Session Handle */
    char errbuf[PCAP_ERRBUF_SIZE]; /* Error Buffer */
    struct pcap_pkthdr pkthdr; /* Packet Infomation */
    const u_char * packet = NULL; /* Received Raw Data */
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
        printf("Payload:\n");
        for (int i = 0; i < pkthdr.len; i++) {
            if (isprint(packet[i])) { // 可打印字符
                printf("%c ", packet[i]);
            } else {
                printf(". ");
            }

            if (((i % 16) == 0 && i != 0) || i == pkthdr.len - 1) {
                printf("\n");
            }
        }
    }
    if (packet == NULL) {
        fprintf(stderr, "pcap_next error: %s\n", pcap_geterr(handle));
        exit(1);
    }
    return 0;
}