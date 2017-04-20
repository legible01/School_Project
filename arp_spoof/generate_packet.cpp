#include "generate_packet.h"
#include "libnet-headers.h"
#include <cstdio>
#include <vector>
generate_packet::generate_packet(int pack_count)
{
    arp_spoof_num = pack_count;//packet number
    for(int i =0;i<arp_spoof_num;i++){
        arp_spoof_pack[i].resize(LIBNET_ETH_H + LIBNET_ARP_ETH_IP_H);//that need heap mem del?
    }
}
    void generate_packet :: proto_packet_set(){
    for(int i =0;i<arp_spoof_num;i++){
        libnet_ethernet_hdr * ether_hdr_part = &arp_spoof_pack[i][0]


    }

}
