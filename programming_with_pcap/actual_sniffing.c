/**
 * @file actual_sniffing.c
 * @author seed
 * @brief actually capture some packets
 * capture a single packet
 * @version 0.1
 * @date 2022-07-06
 * 
 * @copyright Copyright (c) 2022
 * 
 */
#include <pcap.h>
#include <stdio.h>
int main(int argc, char *argv[]) {
    pcap_t *handle; /* Session handle */
    char *dev; /* The device to sniff on */
    char errbuf[PCAP_ERRBUF_SIZE]; /* Error String */
    struct bpf_program fp; /* The compiled filter */
    char filter_exp[] = "icmp"; /* The filter expression */
    bpf_u_int32 net; /* Our IP */
    bpf_u_int32 mask; /* Our netmask */
    struct pcap_pkthdr header; /* The header that pcap gives us */
    const u_char *packet; /* The actual packet */

    /* Define the device */
    if ((dev = pcap_lookupdev(errbuf)) == NULL) {
        fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
        return 2;
    }
    /* Find the properties for the device */
    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
        net = 0;
        mask = 0;
    }
    /* Open the session in promiscous mode */
    if((handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf)) == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return 2;
    }
    /* Compile and apply the filter */
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return 2;
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
    }
    /* Grab a packet */
    packet = pcap_next(handle, &header);
    /* Print its length */
    printf("Jacked a packet with length of [%d]\n", header.len);
    /* And close the session */
    pcap_close(handle);
    return 0;
}
