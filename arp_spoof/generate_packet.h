#ifndef GENERATE_PACKET_H
#define GENERATE_PACKET_H
#include <stdint.h>
#include "libnet-headers.h"
#include "packet_info.h"
#include <vector>

#pragma pack(push, 1)
struct arp_header_ip{

    uint8_t src_mac[6];
    uint32_t src_ip;
    uint8_t dst_mac[6];
    uint32_t dst_ip;

};//packet_info.arp_ip
#pragma pack(pop)

class generate_packet
{
private:
    int arp_spoof_num;
    uint8_t** my_mac;
    uint32_t* my_ip;
    uint8_t** sender_mac;
    uint32_t* sender_ip;
    uint8_t** target_mac;
    uint32_t* target_ip;



    std ::vector<std::vector<uint8_t> >arp_spoof_pack;

public:
    generate_packet(int pack_count);
    void arp_reply_set(packet_info& pack_info);
    void send_arp_reply(pcap_t * pack_d,int num);//if num = zero max,
   // void send_arp_packet(pcap_t *pack_d,int num);

    void edit_info_reply(ip ip);


    //dmac smac eth_type arp_info smac sip dmac dip
    //just need mac
};

#endif // GENERATE_PACKET_H

