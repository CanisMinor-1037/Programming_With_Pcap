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
    char effbuf[PCAP_ERRBUF_SIZE]; /* Error String */
    struct bpf_program fp; /* The compiled filter */
    char filter_exp[] = "icmp"; /* The filter expression */
}
