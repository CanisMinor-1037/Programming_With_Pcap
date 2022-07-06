/**
 * @file setting_the_device.c
 * @author seed
 * @brief https://www.tcpdump.org/pcap.html 
 * begin by determining which interface we want to sniff on
 * ask pcap to provide us with the name of an interface that will do the job
 * technique-2: pcap just sets the device on its own
 * @version 0.1
 * @date 2022-07-06
 * @copyright Copyright (c) 2022
 * 
 */
#include <stdio.h>
#include <pcap.h>
int main(int argc, char *argv[]) {
    /**
     * @brief errbug string
     * In the event that the command fails,
     * it will populate the string with a description of the error.
     * In this case, if pcap_lookupdev(3PCAP) fails, 
     * it will store an error message in errbuf
     */
    char *dev, errbuf[PCAP_ERRBUF_SIZE];
    dev = pcap_lookupdev(errbuf);
    if (dev == NULL) {
        fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
        return 2;
    }
    printf("Device: %s\n", dev);
    return(0);
}