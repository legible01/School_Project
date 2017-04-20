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
#include <vector>

#define SENDER_FLAG     1
#define TARGET_FLAG     2


int packet_info :: get_param_count()
{
    return param_count;//[param_count];//save data with pton.
}

void packet_info :: allocate_param(int p_count,char *param_dev)
{
    dev_name = param_dev;
    printf(" %s ",dev_name);

    param_count = (p_count-2)/2;
    printf("paramcount %d\n",param_count);


    sender_ip.resize(param_count);
    target_ip.resize(param_count);
    sender_mac.resize(param_count);
    target_mac.resize(param_count);

    for(int i =0;i<param_count;i++){
        sender_mac[i].resize(6);//must make delete heap memory
        target_mac[i].resize(6);//= new uint32_t[param_count][6];
    }
      //friend class generate_packet;
      //this part initialize
      //uint8_t **sender_mac;//[param_count][6] //= new uint32_t[param_count][6];
    //6 size of mac + argument number


}

void packet_info :: set_param_ip(char **param_ip)//param input
{

    printf("\nis work?\n\n");
    for(int i=0;i<param_count;i++){
        printf("pack %d \n",i);
        inet_pton(AF_INET,param_ip[2*i],&sender_ip[i]);
        inet_pton(AF_INET,param_ip[2*i+1],&target_ip[i]);

    }
    for(int i=0;i<param_count;i++){
        printf("\n\nparam sender,target: %x %x \n\n",sender_ip[i],target_ip[i]);
        printf("\n\nparam sender,target: %x %x \n\n",&param_ip[2*i],&param_ip[2*i+1]);
    }
}
void packet_info ::  set_param_mac(pcap_t * pack_d)//*************************************************************************************
{
    arp_req_common_set();


    //arp_common_info((struct arp_hdr *)&arp_req_buf[sizeof(ether_header)],pack_info);//edit this part
    //request_ether_info((struct ether_header *)&arp_req_buf,pack_info);
    printf("\n123\n\n");
    for (int i=0;i<param_count;i++){
        get_mac_addr(pack_d,SENDER_FLAG,i);
        get_mac_addr(pack_d,TARGET_FLAG,i);
    }
    printf("\n done sender mac:");
    for(int i=0;i<param_count;i++){
        for(int j=0;j<6;j++){
            printf("%02x \n",sender_mac[i][j]);
        }
        printf("\n");
    }
    printf("\n done target mac:");
    for(int i=0;i<param_count;i++){
        for(int j=0;j<6;j++){
            printf("%02x \n",target_mac[i][j]);
        }
        printf("\n");
    }



}

void packet_info ::  set_my_info()
{

    struct ifreq ifr;
    strcpy(ifr.ifr_name, dev_name);

    printf("\nname %s\n\n",dev_name);
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0) {
        printf("socket error\n");
        return ;
    }
    printf("\nfd value: %d",fd);
    int result = ioctl(fd, SIOCGIFADDR, &ifr);
    printf("vaulu:%d \n",result);
    check_ioctl_err(result);
    memcpy(&this->my_ip,ifr.ifr_addr.sa_data+2,sizeof(uint32_t));// Get IP Adress
    printf("\nmyip: %02x\n",my_ip);
    result = ioctl(fd, SIOCGIFHWADDR, &ifr);
    check_ioctl_err(result);
    memcpy(&this->my_mac,ifr.ifr_hwaddr.sa_data,sizeof(uint8_t)*6);//get mac addr
    for(int i=0;i<6;i++)
        printf("%02x",my_mac[i]);
}
void packet_info :: delete_param_mem()
{
    for(int i =0;i<param_count;++i){
        //delete[] sender_mac[i] ;//delete heap memory
      //  delete[] target_mac[i];
    }
  //  delete[] sender_mac;
    //delete[] target_mac;
    //delete[] sender_ip;
   //delete[] target_ip;

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

    return dev_name;
}
//*************************************************************************

void packet_info :: arp_req_common_set(){
    struct libnet_ethernet_hdr *ether_req_buf=(struct libnet_ethernet_hdr *)arp_req_buf;

    memset(ether_req_buf->ether_dhost,-1,ETHER_ADDR_LEN);

    memcpy(ether_req_buf->ether_shost,&my_mac,ETHER_ADDR_LEN);
    ether_req_buf->ether_type = htons(ETHERTYPE_ARP);

    struct libnet_arp_hdr *arp_req_hdr =(struct libnet_arp_hdr *)&arp_req_buf[LIBNET_ETH_H];
    arp_req_hdr->ar_hrd = htons(ARPHRD_ETHER);
    arp_req_hdr->ar_pro = htons(ETHERTYPE_IP);
    arp_req_hdr->ar_hln=6;
    arp_req_hdr->ar_pln=4;
    arp_req_hdr->ar_op = htons(ARPOP_REQUEST);

    struct arp_header_ip *arp_add_info =(struct arp_header_ip *)&arp_req_buf[LIBNET_ETH_H+LIBNET_ARP_H];
    memcpy(arp_add_info->src_mac,&my_mac,ETHER_ADDR_LEN);//my mac->sender hw
    memcpy((uint32_t *)&arp_add_info->src_ip,&my_ip,sizeof(uint32_t));//my ip->sender ip ** cast pointer different size
    memset(arp_add_info->dst_mac,0,ETHER_ADDR_LEN);//target hw 0

}


void packet_info :: get_mac_addr(pcap_t * pack_d,int flag,int count)//pd,&pack_info,pack_info.sender_ip
{
    //packet_descript,maked buf adress,this.ipspace_buf
    //edit dst ip info

    request_arp_info(count,flag);

    for(int i=0;i<42;i++){
        printf("%02x   ",arp_req_buf[i]);
        //printf("\nsize :%d\n",sizeof(ether_req_buf->ether_dhost));
    }
    printf("\n\n");
    send_arp_packet(pack_d);
    printf("\n\n");

    int loopstatus = 0;
    const uint8_t *pkt_data;
    struct pcap_pkthdr *pkt_hdr;

    printf("\n\nhere1?");
    while((loopstatus = pcap_next_ex(pack_d, &pkt_hdr, &pkt_data)) >= 0){//pkt_data 's adress
        (void)pkt_hdr;//useless
        printf("\n\nhere1\n %d \n",loopstatus);
        if(loopstatus == 0)
            continue;

        if(ether_check((struct libnet_ethernet_hdr *)pkt_data)== -1)
            continue;

        if(arp_check((uint8_t *)pkt_data,flag,count) == -1)//packet_data,ip,info_struc
            continue;//return value 0 then mov next function and if value -1 then restart loop


        printf("end1;");
        printf("\nhere2?");
        printf("\nGet MacAddress Done.\n");

        break;

    }
    if(loopstatus == -1 || loopstatus == -2)
        pcap_perror(pack_d,"Packet data read error");



}

void  packet_info :: request_arp_info(int count,int flag)
{
    struct arp_header_ip *arp_add_info =(struct arp_header_ip *)&arp_req_buf[LIBNET_ETH_H+LIBNET_ARP_H];
    if(flag == SENDER_FLAG)
        memcpy(&arp_add_info->dst_ip,&sender_ip[count],sizeof(uint32_t));//input ip adr to get mac!
    else
        memcpy(&arp_add_info->dst_ip,&target_ip[count],sizeof(uint32_t));
}

void  packet_info :: send_arp_packet(pcap_t *pack_d)
{
    printf("size of packet %d\n\n",sizeof(arp_req_buf));
    printf("%p\n\n",arp_req_buf);
    //int result =;
    if(pcap_sendpacket(pack_d,arp_req_buf,sizeof(arp_req_buf)) !=0)
        pcap_perror(pack_d,"packet send error\n\n");
    printf("donr\n\n");
    return;
}

int  packet_info :: ether_check(struct libnet_ethernet_hdr* ether_reply_buf)
{

    if(ntohs(ether_reply_buf->ether_type) == ETHERTYPE_ARP){//if arp packet pass
        printf("\n ntoh %x\n ",ntohs(ether_reply_buf->ether_type));
        return 0;}
    else
        return -1;
}


int  packet_info :: arp_check(uint8_t *packet,int flag,int count)//,uint8_t *struc_info_mac,
{
    libnet_arp_hdr * arp_reply_hdr =(libnet_arp_hdr *)&packet[LIBNET_ETH_H];
    printf("123 %02x     \n\n",ntohs(arp_reply_hdr->ar_op));
    if(ntohs(arp_reply_hdr->ar_op) != ARPOP_REPLY)//arp_opcode check
        return -1;
    struct arp_header_ip *arp_reply_info = (struct arp_header_ip *)&packet[LIBNET_ETH_H+LIBNET_ARP_H];
                     //right ip then get mac
    printf("\nsneder?: %x\n",sender_ip[count]);
    printf("%x \n",sender_ip[count]);
    printf("%x \n",arp_reply_info->src_ip);


    switch(flag){
        case SENDER_FLAG:
        {
            if(memcmp(&sender_ip[count],&arp_reply_info->src_ip,sizeof(uint32_t))== 0){
                //( == 0
                memcpy(&sender_mac[count][0],arp_reply_info->src_mac,ETHER_ADDR_LEN);//how can i choose area
                return 0;
            }else
                return -1;
        }
        case TARGET_FLAG:
        {
            if(memcmp(&target_ip[count],&arp_reply_info->src_ip,sizeof(uint32_t)) == 0){
                //ntohl(arp_reply_info->src_ip) == target_ip[count]
                memcpy(&target_mac[count][0],arp_reply_info->src_mac,ETHER_ADDR_LEN);//how can i choose area
                return 0;
            }else
                return -1;
        }

    }

}




