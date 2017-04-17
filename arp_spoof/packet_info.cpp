#include "packet_info.h"
#include "libnet-headers.h"
#include <stdint.h>
#include <cstdio>
#include <cstring>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <cstring>
#include <arpa/inet.h>
#include <net/if.h>
#include <pcap.h>

#pragma pack(push, 1)
struct arp_header_ip{

    uint8_t src_mac[6];
    uint32_t src_ip = 4;
    uint8_t dst_mac[6];
    uint32_t dst_ip;

};//packet_info.arp_ip
#pragma pack(pop)


void packet_info :: allocate_param_mem(int p_count,char *param_dev)
{
    dev_name = param_dev;
    param_count = (p_count-2)/2;
    sender_mac = new uint8_t*[param_count];
    target_mac = new uint8_t*[param_count];
    for(int i =0;i<param_count;i++){
        sender_mac[i] = new uint8_t[6];//must make delete heap memory
        target_mac[i] = new uint8_t[6];//= new uint32_t[param_count][6];
    }
    //6 size of mac + argument number
    sender_ip = new uint32_t[param_count];
    target_ip = new uint32_t[param_count];//save data with pton.

}

void packet_info :: set_param_ip(char **param_ip)//param input
{

    for(int i=0;i<param_count;i++){
        printf("pack %d ",i);
        inet_pton(AF_INET,param_ip[2*i],&sender_ip[i]);
        inet_pton(AF_INET,param_ip[2*i+1],&target_ip[i]);
        printf("param sender,target: %x %x \n\n",sender_ip[i],target_ip[i]);
    }
}
void packet_info ::  set_param_mac(pcap_t * pack_d)//*********************************************************************
{

    uint8_t arp_req_buf[sizeof(LIBNET_ETH_H + LIBNET_ARP_ETH_IP_H )];

    arp_req_common_set(arp_req_buf);
    //arp_common_info((struct arp_hdr *)&arp_req_buf[sizeof(ether_header)],pack_info);//edit this part
    //request_ether_info((struct ether_header *)&arp_req_buf,pack_info);
    for (int i=0;i<param_count;i++){
        get_mac_addr(pack_d,arp_req_buf,&sender_ip[i]);
        get_mac_addr(pack_d,arp_req_buf,&target_ip[i]);
    }

}

void packet_info ::  set_my_info()
{

    struct ifreq ifr;
    strcpy(ifr.ifr_name, dev_name);

    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0) {
        printf("socket error\n");
        return ;
    }

    int result = ioctl(fd, SIOCGIFADDR, &ifr);
    check_ioctl_err(result);
    memcpy(&this->my_ip,ifr.ifr_addr.sa_data+2,sizeof(uint32_t));// Get IP Adress

    result = ioctl(fd, SIOCGIFHWADDR, &ifr);
    check_ioctl_err(result);
    memcpy(&this->my_mac,ifr.ifr_hwaddr.sa_data,sizeof(uint8_t)*6);//get mac addr
}
void packet_info :: delete_param_mem()
{
    for(int i =0;i<param_count;++i){
        delete[] sender_mac[i] ;//delete heap memory
        delete[] target_mac[i];
    }
    delete[] sender_mac;
    delete[] target_mac;
    delete[] sender_ip;
    delete[] target_ip;

}
void packet_info ::check_ioctl_err(int ioctl_flag)
{
        if (ioctl_flag < 0){
            printf("getHardInfo Error");
            return;
        }
        return;
}
char* packet_info ::get_my_dev(){

    return this->dev_name;
}
//*************************************************************************

void packet_info :: arp_req_common_set(struct libnet_ethernet_hdr* ether_req_buf){
    //void request_ether_info(struct ether_header *eth_p,packet_info& pack_info)//edit this part
    //for(int i=0;i<6;i++)
    //    arp_req_buf->ether_dhost[i]=0xff;
    memset(ether_req_buf->ether_dhost,-1,ETHER_ADDR_LEN);
    memcpy(ether_req_buf->ether_shost,&my_mac,sizeof(uint8_t)*6);
    ether_req_buf->ether_type = htons(ETHERTYPE_ARP);

    struct libnet_arp_hdr *arp_req_buf =(struct libnet_arp_hdr *)&ether_req_buf[LIBNET_ETH_H];
    arp_req_buf->ar_hrd = htons(ARPHRD_ETHER);
    arp_req_buf->ar_pro = htons(ETHERTYPE_IP);
    arp_req_buf->ar_hln=6;
    arp_req_buf->ar_pln=4;

    struct arp_header_ip *arp_add_info =(struct arp_header_ip *)&arp_req_buf[LIBNET_ARP_H];
    memcpy(arp_add_info->src_mac,&my_mac,sizeof(uint8_t)*6);//my mac->sender hw

}
void request_arp_info(struct arp_hdr *arp_p,packet_info& pack_info,int flag)
{

    memcpy(&arp_p->ar_sip,&pack_info.get_info_my_ip(),sizeof(uint32_t));//my ip->sender ip **
    if(flag == SENDER_FLAG)
        memcpy(&arp_p->ar_tip,&pack_info.get_info_sender_ip(),sizeof(uint32_t));//sender ip->target ip
    else if(flag == TARGET_FLAG)
        memcpy(&arp_p->ar_tip,&pack_info.get_info_target_ip(),sizeof(uint32_t));//sender ip->target ip

    for(int i=0;i<6;i++)
        arp_p->ar_tha[i]=0;                         //target hw 0 fix this.

    arp_p->ar_op = htons(ARPOP_REQUEST);//if i send arp request then need it **

}

void packet_info :: get_mac_addr(pcap_t * pack_d,uint8_t *arp_req_buf,uint32_t *ip)//pd,&pack_info,pack_info.sender_ip
{

    request_arp_info((struct arp_hdr *)&arp_req_buf[sizeof(ether_header)],pack_info,flag);


    send_arp_packet((uint8_t *)&arp_req_buf,pack_d,sizeof(arp_req_buf));

    int loopstatus = 0;
    const uint8_t *pkt_data;
    struct pcap_pkthdr *pkt_hdr;

    printf("\n\nhere1?");
    while((loopstatus = pcap_next_ex(pack_d, &pkt_hdr, &pkt_data)) >= 0){//pkt_data 's adress
        (void)pkt_hdr;//useless
        printf("\n\nhere1\n");
        if(loopstatus == 0)
            continue;//timeout check

        if(ether_check((ether_header *)pkt_data)== -1)
            continue;
        printf("\nhere2.1?\n");
        if(arp_check((uint8_t *)pkt_data,pack_info,flag) == -1)//packet_data,ip,info_struc
            continue;//return value 0 then mov next function and if value -1 then restart loop
        printf("\nhere2?");
        printf("\nGet MacAddress Done.\n");

        break;

    }
    if(loopstatus == -1 || loopstatus == -2){
        pcap_perror(pack_d,"Packet data read error");
        break;
    }



}




int ether_check(struct ether_header *pack1)
{
    uint16_t check_eth_type = pack1->ether_type;

    if(ntohs(check_eth_type) == ETHERTYPE_ARP)//if arp packet pass
        return 0;
    else
        return -1;
}


int arp_check(uint8_t *pack2,packet_info& pack_info,int flag)//,uint8_t *struc_info_mac,
{
    struct arp_hdr *arp_data1 =(struct arp_hdr *)&pack2[sizeof(ether_header)];

    if(ntohs(arp_data1->ar_op) != ARP_REPLY)//arp_opcode check
        return -1;
    switch(flag){
        case SENDER_FLAG:
            if(arp_data1->ar_sip == pack_info.get_info_sender_ip()){//right ip then get mac
                pack_info.set_info_sender_mac(arp_data1->ar_sha);
                //memcpy(input_mac,arp_data1->ar_sha,sizeof(uint8_t)*6);
                return 0;
            }else
                return -1;

        case TARGET_FLAG:
            if(arp_data1->ar_sip == pack_info.get_info_target_ip()){//right ip then get mac
                pack_info.set_info_target_mac(arp_data1->ar_tha);
                //memcpy(input_mac,arp_data1->ar_sha,sizeof(uint8_t)*6);
                return 0;
            }else
                return -1;


    }
    return -1;
}








void send_arp_packet(uint8_t *send_arp,pcap_t *pack_d,int packet_size)
{
    int result =pcap_sendpacket(pack_d,send_arp,packet_size);
    if(result !=0)
        pcap_perror(pack_d,"packet send error");

    return;
}
