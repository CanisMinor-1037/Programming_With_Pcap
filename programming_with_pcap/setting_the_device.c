/**
 * @file setting_the_device.c
 * @author seed
 * @brief https://www.tcpdump.org/pcap.html 
 * begin by determining which interface we want to sniff on
 * ask pcap to provide us with the name of an interface that will do the job
 * technique-1:  simply have the user tell us
 * @version 0.1
 * @date 2022-07-06
 * 
 * @copyright Copyright (c) 2022
 * 
 */
#include <stdio.h>
#include <pcap.h>
int main(int argc, char *argv[]) {
    
    char *dev = argv[1];
    printf("Device: %s\n", dev);
    return 0;
}