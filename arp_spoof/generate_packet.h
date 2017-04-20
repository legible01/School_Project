#ifndef GENERATE_PACKET_H
#define GENERATE_PACKET_H
#include <stdint.h>
#include "libnet-headers.h"
#include <vector>
/*
#pragma pack(push, 1)
struct arp_header_ip{

    uint8_t src_mac[6];
    uint32_t src_ip = 4;
    uint8_t dst_mac[6];
    uint32_t dst_ip;

};//packet_info.arp_ip
#pragma pack(pop)*/

class generate_packet
{
private:
    int arp_spoof_num;
    std ::vector<std::vector<uint8_t> >arp_spoof_pack;

public:
    generate_packet(int pack_count);
    void proto_packet_set();

    void edit_info_reply(ip ip);


    //dmac smac eth_type arp_info smac sip dmac dip
    //just need mac
};

#endif // GENERATE_PACKET_H

