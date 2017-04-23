#ifndef PACKET_INFO_H
#define PACKET_INFO_H
#include "libnet-headers.h"
#include <stdint.h>
#include <pcap.h>
#include "packet_info.h"
#include <vector>
#include <array>


class packet_info
{
private:
    friend class generate_packet;
    char *dev_name;

    uint8_t my_mac[6];
    uint8_t broadcast_d_mac[6];
    uint32_t my_ip;
    int param_count;
    std ::vector<std::vector<uint8_t> >sender_mac;// arr(param_count, vector<int>(5, 0));
    std ::vector<std::vector<uint8_t> >target_mac;// arr(param_count, vector<int>(5, 0));

    std ::vector<uint32_t>sender_ip;
    std ::vector<uint32_t>target_ip;

    uint8_t arp_req_buf[LIBNET_ETH_H + LIBNET_ARP_ETH_IP_H];

#pragma pack(push, 1)
struct arp_header_ip{

    uint8_t src_mac[6];
    uint32_t src_ip;
    uint8_t dst_mac[6];
    uint32_t dst_ip;

};//packet_info.arp_ip
#pragma pack(pop)

public:
    int get_param_count();
    void allocate_param(int p_count,char *param_dev);
    void set_param_ip(char **param_ip);//param input
    void set_param_mac(pcap_t * pack_d);
    void delete_param_mem();//var delete
    void set_my_info();
    void check_ioctl_err(int ioctl_flag);

    char* get_my_dev();
    void arp_req_common_set();

    void request_arp_info(int count,int flag);
    int arp_check(uint8_t *packet,int flag,int count);
    void send_arp_packet(pcap_t *pack_d);
    void get_mac_addr(pcap_t * pack_d,int flag,int count);

    int  ether_check(struct libnet_ethernet_hdr* ether_req_buf);
    uint32_t* sender_ip_ref(int num);
    uint32_t* target_ip_ref(int num);
    uint8_t* my_mac_ref();
    uint8_t* sender_mac_ref(int num);
    uint8_t* broad_ff_ref();
    uint8_t* target_mac_ref(int num);
    uint32_t* my_ip_ref();

};



#endif // PACKET_INFO_H
