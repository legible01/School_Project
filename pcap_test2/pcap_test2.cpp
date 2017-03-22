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

#define PROMISCUOUS 1;
#define NON PROMISCUOUS 0;

char *correct_dev(int argu_count,char *argu_vector);

void packet_control(pcap_t * pack_descript);//this function include every functions under this code.
int ether_print(u_char **pack);
void print_mac(const u_char * mac_adr,char const *mac_info);
int iph_print(u_char **iph_p,int *tcplen_p);
void print_ip(const void *ip_add_p,char const *ip_info);
int tcph_print(u_char **tcph_p,int * tcplen_p);
void tcpd_print(u_char **tcpd_p,int tcpd_len);
void findhostadr(u_char **data_p,int tcpd_len);




int main(int argc, char *argv[]) {

    char errbuf[PCAP_ERRBUF_SIZE];
    int flags = PROMISCUOUS;

    char *dev = correct_dev(argc,argv[1]);//check device argument
    pcap_t * packetDescriptor = pcap_open_live(dev, BUFSIZ, flags, 300, errbuf);
    if(packetDescriptor == NULL) {
        printf("%s\n",errbuf);
        exit(1);
    }else
        packet_control(packetDescriptor);
    return 0;
}


//functions

    //check device argument
char *correct_dev(int argu_count,char *argu_vector)
{
    if (argu_count != 2){
        printf("use this form to use program\nProgramName DeviceName\n");
        exit(1);
    }
    printf("Device : %s\n", argu_vector);
    return argu_vector;
}

    //print packet
void packet_control(pcap_t * pack_descript)
{

    int loopstatus = 0;
    int tcpd_len = 0;
    const u_char *pkt_data;
    struct pcap_pkthdr *pkt_hdr;

    while((loopstatus = pcap_next_ex(pack_descript, &pkt_hdr, &pkt_data)) >= 0){//pkt_data 's adress
       (void)pkt_hdr;//useless

        if(loopstatus == 0)
            continue;//timeout check

        u_char * packet_p=(u_char *)pkt_data;//pkt_data->data(adress)

        if(ether_print(&packet_p)== -1)
            continue;
        if(iph_print(&packet_p,&tcpd_len) == -1)
            continue;//return value 0 then mov next function and if value -1 then restart loop
        if(tcph_print(&packet_p,&tcpd_len) == -1)
            continue;
        findhostadr(&packet_p,tcpd_len);
        tcpd_print(&packet_p,tcpd_len);

    }
    if(loopstatus == -1 || loopstatus == -2)
          pcap_perror(pack_descript,"Packet data read error");

}


int ether_print(u_char **pack)
{

    struct ether_header *ep = (struct ether_header *)*pack;//get ether header

    printf("\n-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*\n\nEthernet Header\n");
    print_mac(ep->ether_shost,"src mac adress: ");//Mac address output
    print_mac(ep->ether_dhost,"Dst mac adress: ");

    u_short ether_type = ntohs(ep->ether_type);//ether_type ==0x0800
    if (ether_type == ETHERTYPE_IP){
       *pack= *pack + sizeof(*ep);
        return 0;
    }else{
        printf("\nnot IP protocols\n");
        return -1;
    }


}

void print_mac(const u_char * mac_adr,char const *mac_info)
{
    printf("\n%s : ",mac_info);
    for(int i=0;i<6;i++){
        printf ("%02X ", *(mac_adr+i));
    }
}


int iph_print(u_char **iph_p,int *tcplen_p)//ip area
{
    struct ip *iph = (struct ip *)*iph_p;

    printf("\n\nIP Header\n");
    print_ip(&(iph->ip_src),"Src IP Address");
    print_ip(&(iph->ip_dst),"Dst IP Address");


    if (iph->ip_p == IPPROTO_TCP){  //ip_p == 8 Tcp port output
        *iph_p = *iph_p+sizeof(ip);
        *tcplen_p = ntohs(iph->ip_len)-sizeof(*iph);//calc ip_total_length - ip_header
        return 0;
    }else{
        printf("\nthis packet is not TCP Protocols\n");
        return -1;
    }

}

void print_ip(const void *ip_add_p,char const *ip_info)
{
    char ip_buf[17];//ntop data

    inet_ntop(AF_INET,ip_add_p,ip_buf,16);//src ip output         make function
    printf("%s : %s \n",ip_info,ip_buf);
}


int tcph_print(u_char ** tcph_p,int * tcplen_p)
{
    struct tcphdr *tcph;
    tcph = (struct tcphdr *)*tcph_p;//data adress

    printf("\nTCP Protocol\n");
    printf("Src Port : %d\n" , ntohs(tcph->source));
    printf("Dst Port : %d\n" , ntohs(tcph->dest));
    printf("seq: %d\n",ntohs(tcph->th_seq));

    //payload output
    *tcplen_p = *tcplen_p - sizeof(*tcph);//calc paylen
    if (*tcplen_p != 0){
        *tcph_p = *tcph_p +sizeof(*tcph);
        printf("\npayload len:%d \n\n",*tcplen_p); //check output data
        return 0;
    }else{
        printf("\nNO PAYLOAD DATA\n");
        return -1;
    }

}


void tcpd_print(u_char ** tcpd_p,int tcpd_len)
{
    int chcnt =0;
    u_char *tcpdata = *tcpd_p;

    printf("\n\npayload hexa Value\n\n");   //Hexa output area
    while(tcpd_len--){
        printf("%02x ", *(tcpdata++));
        if ((++chcnt % 16) == 0)
            printf("\n");
        else if(tcpd_len == 0)
            return;
    }
}


void findhostadr(u_char ** data_p,int tcpd_len)
{
    uint8_t * data_byte = *data_p;
    uint32_t * h_name_start = (uint32_t *)data_byte;
    while((tcpd_len--)!=0){
        if(*h_name_start == ntohl(0x486f7374)){

            uint16_t *h_name_end = (uint16_t *)data_byte;
            while(*h_name_end != ntohs(0x0d0a)){
                printf("%c",*data_byte); //print == \r\n
                h_name_end =(uint16_t *)(++data_byte);
            }
            return;
        }else
           h_name_start =(uint32_t *)(++data_byte);//1 byte memory move
    }
    printf("\nNO TCP HOST ADR AREA IN DATA");
}










