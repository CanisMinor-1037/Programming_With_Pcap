/**
 * @file filtering_traffic.c
 * @author seed
 * @brief 
 * After we have already called pcap_open_live() 
 * and have a working sniffing session, 
 * we can apply our filter with pcap_compile() and pcap_setfilter()
 * @version 0.1
 * @date 2022-07-06
 * 
 * @copyright Copyright (c) 2022
 * 
 */
#include <pcap.h>
int main(int argc, char *argv[]) {
    char *dev = argv[1]; /* Device to sniff on */
    printf("Device: %s\n", dev);
    
    char errbuf[PCAP_ERRBUF_SIZE]; /* Error String */
    
    pcap_t *handle; /* Session handle */
    
    char filter_exp[] = "icmp"; /* The filter expression */
    struct bpf_program fp; /* The compiled filter expression */
    bpf_u_int32 mask; /* The netmask of our sniffing device */
    bpf_u_int32 net; /* The IP of our sniff device */

    /**
     * @brief 
     * given the name of a device,
     * returns one of its IPv4 network numbers and corresponding network mask 
     * (the network number is the IPv4 address ANDed with the network mask, 
     * so it contains only the network part of the address)
     */
    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Can't get netmask for device %s\n", dev);
        net = 0;
        mask = 0;
    }

    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return 2;
    }
    /**
     * @brief If your program doesn't support the link-layer header type provided by the device, 
     * it has to give up; this would be done with code such as:
     */
    if (pcap_datalink(handle) != DLT_EN10MB) {
	    fprintf(stderr, "Device %s doesn't provide Ethernet headers - not supported\n", dev);
	    return 2;// which fails if the device doesn't supply Ethernet headers
    }
    /**
     * @brief pcap_compile()
     * @param p:pcap_t *:session handle:handle 
     * @param fp:struct bpf_program *:store the compiled version of the filter:&fp
     * @param str:char *:the filter expression:filter_exp
     * @param optimize:int:decides if the expression should be "optimized" or not (0 is false, 1 is true—standard stuff):0
     * @param netmask:bpf_u_int32:the network mask of the network the filter applies to:net
     * @return int: -1 on failure
     */
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return 2;
    }
    /**
     * @brief pcap_setfilter
     * @param p:pcap_t *:session handler:handle
     * @param fp:struct bpf_program *:the compiled version of the filter expression:&fp
     * @return int: -1 on failure
     */
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return 2;
    }

    return 0;
}