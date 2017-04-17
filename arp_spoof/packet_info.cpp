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
void packet_info ::  set_param_mac(pcap_t * pack_d)//*************************************************************************************
{

    uint8_t arp_req_buf[sizeof(LIBNET_ETH_H + LIBNET_ARP_ETH_IP_H )];

    arp_req_common_set((struct libnet_ethernet_hdr*)arp_req_buf);
    //arp_common_info((struct arp_hdr *)&arp_req_buf[sizeof(ether_header)],pack_info);//edit this part
    //request_ether_info((struct ether_header *)&arp_req_buf,pack_info);
    for (int i=0;i<param_count;i++){
        get_mac_addr(pack_d,arp_req_buf,&sender_ip[i],&sender_mac[i][0]);
        get_mac_addr(pack_d,arp_req_buf,&target_ip[i],&target_mac[i][0]);
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
    arp_req_buf->ar_op = htons(ARPOP_REQUEST);

    struct arp_header_ip *arp_add_info =(struct arp_header_ip *)&arp_req_buf[LIBNET_ARP_H];
    memcpy(arp_add_info->src_mac,&my_mac,ETHER_ADDR_LEN);//my mac->sender hw
    memcpy((uint32_t *)arp_add_info->src_ip,&my_ip,sizeof(uint32_t));//my ip->sender ip ** cast pointer different size
        //arp_p->ar_op = htons(ARPOP_REQUEST);//if i send arp request then need it **
    memset(arp_add_info->dst_mac,0,ETHER_ADDR_LEN);//target hw 0

}


void packet_info :: get_mac_addr(pcap_t * pack_d,uint8_t *arp_req_buf,uint32_t *ip,uint8_t *mac)//pd,&pack_info,pack_info.sender_ip
{
    //packet_descript,maked buf adress,this.ipspace_buf

    request_arp_info((struct arp_header_ip *)&arp_req_buf[LIBNET_ETH_H + LIBNET_ARP_H],ip);
    //edit dst ip info

    send_arp_packet((uint8_t *)&arp_req_buf,pack_d);

    int loopstatus = 0;
    const uint8_t *pkt_data;
    struct pcap_pkthdr *pkt_hdr;

    printf("\n\nhere1?");
    while((loopstatus = pcap_next_ex(pack_d, &pkt_hdr, &pkt_data)) >= 0){//pkt_data 's adress
        (void)pkt_hdr;//useless
        printf("\n\nhere1\n");
        if(loopstatus == 0)
            continue;

        if(ether_check((struct libnet_ethernet_hdr *)pkt_data)== -1)
            continue;
        printf("\nhere2.1?\n");
        if(arp_check((struct libnet_arp_hdr *)pkt_data[LIBNET_ETH_H],ip,mac) == -1)//packet_data,ip,info_struc
            continue;//return value 0 then mov next function and if value -1 then restart loop
        printf("\nhere2?");
        printf("\nGet MacAddress Done.\n");

        break;

    }
    if(loopstatus == -1 || loopstatus == -2)
        pcap_perror(pack_d,"Packet data read error");



}

void  packet_info :: request_arp_info(struct arp_header_ip *arp_add_info,uint32_t *ip)
{
    memcpy(&arp_add_info->dst_ip,ip,sizeof(uint32_t));//sender ip->target ip
}


int  packet_info :: ether_check(struct libnet_ethernet_hdr* ether_reply_buf)
{
    if(ntohs(ether_reply_buf->ether_type) == ETHERTYPE_ARP)//if arp packet pass
        return 0;
    else
        return -1;
}


int  packet_info :: arp_check(struct libnet_arp_hdr *arp_reply_buf,uint32_t *ip ,uint8_t * mac)//,uint8_t *struc_info_mac,
{
    if(ntohs(arp_reply_buf->ar_op) != ARPOP_REPLY)//arp_opcode check
        return -1;
    struct arp_header_ip *arp_reply_info = (arp_header_ip *)&arp_reply_buf[LIBNET_ARP_H];
    if(ntohl(arp_reply_info->src_ip) == *ip){                       //right ip then get mac
        memcpy(mac,arp_reply_info->src_mac,ETHER_ADDR_LEN);//how can i choose area
        return 0;
    }else
        return -1;

}



void  packet_info :: send_arp_packet(uint8_t *send_arp,pcap_t *pack_d)
{
    printf("size of packet %d",sizeof(send_arp));
    int result =pcap_sendpacket(pack_d,send_arp,sizeof(send_arp));
    if(result !=0)
        pcap_perror(pack_d,"packet send error");

    return;
}
