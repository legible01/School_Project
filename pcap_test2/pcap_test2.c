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

//#define UNUSED(p)
struct ip *iph;
struct tcphdr *tcph;
void findhostadr(u_char * hostadr,int strlen);

void show_pac(u_char *none, const struct pcap_pkthdr *pkthdr, const u_char *pack)
{
    (void)none;
    (void)pkthdr;
    //time,lengthof portion present, length this packet

    struct ether_header *ep;//get ether header
    unsigned short ether_type;

    int chcnt =0;
    int ethcnt = 0;//mac address counter
    int paylen = 0;

    u_char *tcpdata;
    u_char *hostadr;
    char buf[17];


//Mac address output
//shost is directly ouput after dhost end

    ep = (struct ether_header *)pack;
    u_char *p =ep->ether_dhost;//use pointer address

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

    if (ether_type == ETHERTYPE_IP)//ether_type ==0x0800
    {
//IP address output
        iph = (struct ip *)pack;

        printf("\nIP Header\n");
        inet_ntop(AF_INET,&(iph->ip_src),buf,16);//src ip output
        printf("Src IP Address : %s \n",buf);

        inet_ntop(AF_INET,&(iph->ip_dst),buf,16);//dst ip output
        printf("Dst IP Address : %s \n",buf);

// Tcp port output
        if (iph->ip_p == IPPROTO_TCP)//ip_p == 8
        {
            tcph = (struct tcphdr *)(pack + iph->ip_hl * 4);
            printf("\nTCP Protocol\n");
            printf("Src Port : %d\n" , ntohs(tcph->source));
            printf("Dst Port : %d\n" , ntohs(tcph->dest));
            printf("seq: %d\n",ntohs(tcph->th_seq));
            paylen=ntohs(iph->ip_len)-((iph->ip_hl*4)+(tcph->doff * 4));
            printf("\npaylen:%d \n\n",paylen);

            if(paylen > 0){
                tcpdata=(u_char *)(pack + (iph->ip_hl * 4) +(tcph->doff * 4));
                hostadr = tcpdata;

        //host data output function
                findhostadr(hostadr,paylen);

        //Hexa output area
                printf("\n\npayload hexa Value\n\n");
                while(paylen--)
                {
                    printf("%02x ", *(tcpdata++));

                    if ((++chcnt % 16) == 0)
                        printf("\n");
                    else if(paylen == 0)
                        break;
                }
            }
            else{
                printf("\nNo Payload Data\n");}

        }else
        {
        printf("\nNot TCP Protocol\n");
        }

     }
// No ip packet
     else
     {
        printf("\nNot IP Packet\n");
     }
      printf("\n-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*\n");

}

void findhostadr(u_char * adr,int strlen)
{
    int result = 0;//statement False
        while((strlen--)!=0)
        {

            if(*adr ==0x48 && *(adr+1) == 0x6f && *(adr+2) == 0x73 && *(adr+3) == 0x74 && *(adr+4) == 0x3a){
                result = 1;//if find Host: change statement True
            }

            if(result == 1)
            {
                printf("%c", *adr);

                if(*(adr+1)==0x0d && *(adr+2)==0x0a)//find \r\n then function is end
                    return;
             }
            adr++;
        }
        printf("\nNO TCP HOST ADR AREA IN DATA\n");
        return;

}

int main(int argc, char *argv[]) {

    char *dev;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *packetDescriptor;

    if (argc != 2)
    {
        printf("use this form to use program\n ");
        printf("ProgramName DeviceName\n");
        printf("your high property device name is %s\n\n",pcap_lookupdev(errbuf));
        exit(1);
    }


    dev = argv[1];//input argv
    printf("Device : %s\n", dev);

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





