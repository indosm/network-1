#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
 int main(int argc, char *argv[])
 {
    pcap_t *handle;			/* Session handle */
    char *dev;			/* The device to sniff on */
    char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
    struct bpf_program fp;		/* The compiled filter */
    char filter_exp[] = "icmp";	/* The filter expression */
    bpf_u_int32 mask;		/* Our netmask */
    bpf_u_int32 net;		/* Our IP */
    struct pcap_pkthdr *header;	/* The header that pcap gives us */
    const u_char *packet;		/* The actual packet */
    const u_char *eptr;	        /* start address of Ethernet*/
    const u_char *ip;           /* start address of IP*/

    u_char *ptr;	/* 네트워크 헤더 정보 출력 */
    /* Define the device */
    dev = pcap_lookupdev(errbuf);
    if (dev == NULL) {
        fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
        return(2);
    }
    /* Find the properties for the device */
    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
        net = 0;
        mask = 0;
    }
    /* Open the session in promiscuous mode */
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return(2);
    }
    /* Compile and apply the filter */
    /*
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return(2);
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return(2);
    }*/
    while(1){
        /* Grab a packet */
        const int rst = pcap_next_ex(handle, &header, &packet);
        if(rst<0)   //can't get packet
            break;
        else if(rst==0)     //get no packet
            continue;
        /* Print its length */
        printf("Jacked a packet with length of [%d]\n", header->len);
        eptr = packet;
        printf("ETHERNET PACKET : \n");
        printf("\tDestination Mac\t: ");
        for(int i=0;i<=5;i++)
        {
            printf("%x%s",*(eptr+i),(i==5?"":":"));
        }
        printf("\n\tSource MAC\t: ");
        for(int i=6;i<=11;i++)
        {
            printf("%x%s",*(eptr+i),(i==11?"":":"));
        }
        printf("\n\t");
        if(ntohs(*(eptr+12))==0x0800)
            printf("IP packet\n");
        else if(ntohs(*(eptr+12))==0x0806){
            printf("ARP packet\n");
            continue;
        }
        else{
            printf("Not IP\n");
            continue;
        }

        printf("\n");

    }
    /* And close the session */
    pcap_close(handle);
    return(0);
 }
