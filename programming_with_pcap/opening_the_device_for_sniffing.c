/**
 * @file opening_the_device_for_sniffing.c
 * @author seed
 * @brief https://www.tcpdump.org/pcap.html
 * use pcap_open_live()
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