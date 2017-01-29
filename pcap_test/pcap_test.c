#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <sys/socket.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

struct ip *iph;
struct tcphdr *tcph;

void show_pac(u_char *none, const struct pcap_pkthdr *pkthdr, const u_char *pack)
{
    //time,lengthof portion present, length this packet

    struct ether_header *ep;//get ether header
    unsigned short ether_type;

    int chcnt =0;
    int ethcnt = 0;//mac address counter
    int length=pkthdr->len;


//Mac address output
//shost is directly ouput after dhost end

    ep = (struct ether_header *)pack;
    u_char *p =ep -> ether_dhost;

    printf("\nEthernet Header\n");
    for(ethcnt =0; ethcnt<12; ethcnt++){
        if(ethcnt == 0)
            printf("Dst Mac Address: ");
        else if(ethcnt == 6)
            printf("\nSrc Mac Address: ");
        printf("%02X ", *(p + ethcnt));
    }


    pack += sizeof(struct ether_header);
    ether_type = ntohs(ep->ether_type);


    if (ether_type == ETHERTYPE_IP)
    {
//IP address output
        iph = (struct ip *)pack;
        printf("\nIP Header\n");
        printf("Src IP Address : %s\n", inet_ntoa(iph->ip_src));
        printf("Dst IP Address : %s\n", inet_ntoa(iph->ip_dst));

// Tcp port output
        if (iph->ip_p == IPPROTO_TCP)
        {
            tcph = (struct tcphdr *)(pack + iph->ip_hl * 4);
            printf("\nTCP Protocol\n");
            printf("Src Port : %d\n" , ntohs(tcph->source));
            printf("Dst Port : %d\n" , ntohs(tcph->dest));
        }
        else
        {
        printf("\nNot TCP Protocol\n");
        }
//Hexa output
        printf("\nHexa Value\n");
        while(length--)
        {
            printf("%02x ", *(pack++));
            if ((++chcnt % 16) == 0)
            printf("\n");
        }
     }
// No ip packet
     else
     {
        printf("\nNot IP Packet\n");
     }
      printf("\n-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*\n");


}

int main(int argc, char *argv[]) {

    char *dev;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *packetDescriptor;
    //decive search

    if(!(dev = pcap_lookupdev(errbuf))) {
        perror(errbuf);
        exit(1);
    }

    printf("Device : %s\n", dev);
    //get NIC name
    packetDescriptor = pcap_open_live(dev, BUFSIZ, 1, 300, errbuf);
    if(packetDescriptor == NULL) {
        printf("%s\n",errbuf);
        exit(1);
    }
    printf("capture success\n");
    printf("\n-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*\n");
    pcap_loop(packetDescriptor, 0, show_pac, 0);
    pcap_close(packetDescriptor);

    return 0;
}






