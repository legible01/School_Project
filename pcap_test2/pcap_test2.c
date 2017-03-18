#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <pcap.h>
#include <sys/socket.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

void show_pac(const u_char *pack);
void findhostadr(u_char * hostadr,int strlen);
char *correct_dev(int argu_count,char *argu_vector,char *errbuf);

int main(int argc, char *argv[]) {

    char *dev;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *packetDescriptor;
    int loopstatus = 0;
    const u_char *pkt_data;
    struct pcap_pkthdr *pkt_hdr;

    //check device argument
    dev = correct_dev(argc,argv[1],errbuf);

    packetDescriptor = pcap_open_live(dev, BUFSIZ, 1, 300, errbuf);
    if(packetDescriptor == NULL) {
        printf("%s\n",errbuf);
        exit(1);
    }
    printf("\n-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*\n");

    while((loopstatus = pcap_next_ex(packetDescriptor, &pkt_hdr, &pkt_data)) >= 0){

        (void)pkt_hdr;

        if(loopstatus == 0){
            continue;//timeout
        }
        show_pac(pkt_data);
    }
    if(loopstatus == -1 || loopstatus == -2){
          pcap_perror(packetDescriptor,"Packet data read error");
          return -1;
    }

    return 0;
}

void show_pac(const u_char *pack)
{
    struct ether_header *ep;//get ether header
    struct ip *iph;
    struct tcphdr *tcph;

    u_short ether_type;

    int chcnt =0;
    int ethcnt = 0;//mac address counter
    int paylen = 0;

    u_char *tcpdata;
    u_char *hostadr;
    char ip_buf[17];

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

    if (ether_type == ETHERTYPE_IP){//ether_type ==0x0800

//IP address output
        iph = (struct ip *)pack;

        printf("\nIP Header\n");
        inet_ntop(AF_INET,&(iph->ip_src),ip_buf,16);//src ip output
        printf("Src IP Address : %s \n",ip_buf);

        inet_ntop(AF_INET,&(iph->ip_dst),ip_buf,16);//dst ip output
        printf("Dst IP Address : %s \n",ip_buf);

// Tcp port output
        if (iph->ip_p == IPPROTO_TCP){  //ip_p == 8

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
                while(paylen--){
                    printf("%02x ", *(tcpdata++));

                    if ((++chcnt % 16) == 0)
                        printf("\n");
                    else if(paylen == 0)
                        break;
                }
            }else{
                printf("\nNo Payload Data\n");
            }

        }else{
        printf("\nNot TCP Protocol\n");
        }

     }else{  // No ip packet
        printf("\nNot IP Packet\n");
     }

      printf("\n-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*\n");

}

void findhostadr(u_char * adr,int strlen)
{
    uint32_t * h_name_start;
    uint16_t * h_name_end;

    while((strlen--)!=0){
        h_name_start = (u_int32_t*)adr;//this start adr and input 4byte data.

        //compare data == HOST
        if(*h_name_start == ntohl(0x486f7374)){

            //compare data == \r\n
            while(*h_name_end!=ntohs(0x0d0a)){
                h_name_end = (uint16_t *)adr;
                printf("%c", *adr);
                adr++;
            }
            break;

        }else
            adr++;
    }

    if(strlen==-1)
        printf("NO TCP HOST ADR AREA IN DATA\n");
}

char *correct_dev(int argu_count,char *argu_vector,char *errbuf)
{
    if (argu_count != 2){
        printf("use this form to use program\n ");
        printf("ProgramName DeviceName\n");
        printf("your high property device name is %s\n\n",pcap_lookupdev(errbuf));
        exit(1);
    }
    printf("Device : %s\n", argu_vector);
    return argu_vector;
}







