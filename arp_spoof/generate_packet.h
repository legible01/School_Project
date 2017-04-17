#ifndef GENERATE_PACKET_H
#define GENERATE_PACKET_H
#include <stdint.h>
#include "libnet-headers.h"

#pragma pack(push, 1)
struct arp_header_ip{

    uint8_t src_mac[6];
    uint32_t src_ip = 4;
    uint8_t dst_mac[6];
    uint32_t dst_ip;

};//packet_info.arp_ip
#pragma pack(pop)

class generate_packet
{
public:
    int num;

    uint32_t my_ip;
    uint32_t target_ip;
    //uint32_t sender_ip[num];
    //uint32_t targer_ip[num];//wtf


    uint8_t reply_pbuf[sizeof(LIBNET_ETH_H + LIBNET_ARP_ETH_IP_H )];//size 14+28
    //struct libnet_ethernet_hdr *reply_eth_h =&reply_pbuf;
    //struct libnet_arp_hdr *reply_arp_h =&reply_pbuf[LIBNET_ETH_H];
    //struct arp_header_ip *reply_arp_ip_h =&reply_pbuf[LIBNET_ETH_H + LIBNET_ARP_H];
    //forced casting

    void proto_packet_set();

    void edit_info_reply(ip ip);

    generate_packet();
    //dmac smac eth_type arp_info smac sip dmac dip
    //just need mac
};

#endif // GENERATE_PACKET_H

