/**
 * @file opening_the_device_for_sniffing.c
 * @author seed 
 * @brief https://www.tcpdump.org/pcap.html
 * use pcap_open_live()
 * @version 0.1
 * @date 2022-07-06
 * @copyright Copyright (c) 2022
 * 
 */
#include <stdio.h>
#include <pcap.h>
int main(int argc, char *argv[]) {    
    char *dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    printf("Device: %s\n", dev);
    pcap_t *handle;
    /**
     * @brief pcap_open_live()
     * @param device : : dev
     * @param snaplen : defines the maximum number of bytes to be captured by pcap : BUFSIZE
     * @param promisc : when set to true, brings the interface into promiscuous mode : 1
     * @param to_ms : the read time out in milliseconds : 1000
     * @param ebuf : a string we can store any error messages within : errbuf
     * @return pcap_t* : session handler : handle
     */
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
    return 0;
}