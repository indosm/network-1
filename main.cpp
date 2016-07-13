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
    bpf_u_int32 mask;		/* Our netmask */
    bpf_u_int32 net;		/* Our IP */
    struct pcap_pkthdr *header;	/* The header that pcap gives us */
    const u_char *packet;		/* The actual packet */
    const u_char *eptr;	        /* start address of Ethernet*/
    const u_char *ip;           /* start address of IP*/
    const u_char *tcp;          /* start address of TCP*/
    int version;
    int length;
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
    while(1){
        /* Grab a packet */
        const int rst = pcap_next_ex(handle, &header, &packet);
        if(rst<0)   //can't get packet
            break;
        else if(rst==0)     //get no packet
            continue;
        /* Print its length */
        printf("------------------------------------------\n");
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
        if(ntohs(*(short*)(eptr+12))==0x0800)
            printf("-> IP packet\n");
        else if(ntohs(*(short*)(eptr+12))==0x0806){
            printf("-> ARP packet\n");
            continue;
        }
        else{
            printf("-> Not IP\n");
            continue;
        }
        // IP Packet
        ip = eptr+14;
        version = (*(char*)(ip))>>4;
        printf("IPv%d PACKET : \n",version);
        length = (*(char*)(ip))-version<<4;
        printf("\tDestination IP\t: ");
        for(int i=12;i<=15;i++)
        {
            printf("%d%s",*(ip+i),(i==15?"":"."));
        }
        printf("\n\tSource IP\t: ");
        for(int i=16;i<=19;i++)
        {
            printf("%d%s",*(ip+i),(i==19?"":"."));
        }
        printf("\n\t");
        if(*(ip+9)==0x6)
            printf("-> TCP packet\n");
        else{
            printf("-> Not TCP\n");
            continue;
        }
        // TCP Packet
        tcp = ip+length;
        printf("TCP PACKET : \n");
        printf("%x %x %x %x\n",*(tcp),*(tcp+1),*(tcp+2),*(tcp+3));
        printf("\tDestination Port: %d",ntohs((*(short*)(tcp+2))));
        printf("\n\tSource Port\t: %d",ntohs((*(short*)(tcp))));
        printf("\n");
    }
    /* And close the session */
    pcap_close(handle);
    return(0);
 }
