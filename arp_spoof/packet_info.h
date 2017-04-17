#ifndef PACKET_INFO_H
#define PACKET_INFO_H
#include <stdint.h>
#include <pcap.h>
#include "packet_info.h"
class packet_info
{
private:
    char *dev_name;

    uint8_t my_mac[6];
    uint32_t my_ip;

    int param_count;
    uint8_t **sender_mac;//[param_count][6] //= new uint32_t[param_count][6];
    uint32_t *sender_ip;//[param_count];
    uint8_t **target_mac;//[param_count][6];//6 size of mac + argument number
    uint32_t *target_ip;//[param_count];//save data with pton.

#pragma pack(push, 1)
struct arp_header_ip{

    uint8_t src_mac[6];
    uint32_t src_ip = 4;
    uint8_t dst_mac[6];
    uint32_t dst_ip;

};//packet_info.arp_ip
#pragma pack(pop)

public:
    void allocate_param_mem(int p_count,char *param_dev);//var create
    void set_param_ip(char **param_ip);//param input
    void set_param_mac(pcap_t * pack_d);
    void delete_param_mem();//var delete
    void set_my_info();
    void check_ioctl_err(int ioctl_flag);

    char* get_my_dev();
    void arp_req_common_set(struct libnet_ethernet_hdr* pack_req_buf);

    void request_arp_info(struct arp_header_ip *arp_add_info,uint32_t *ip);
    int arp_check(struct libnet_arp_hdr *arp_reply_buf,uint32_t *ip ,uint8_t * mac);
    void send_arp_packet(uint8_t *send_arp,pcap_t *pack_d);


    void get_mac_addr(pcap_t * pack_d,uint8_t *arp_req_buf,uint32_t *ip,uint8_t *mac);

    int  ether_check(struct libnet_ethernet_hdr* ether_req_buf);
    //void set_param_ip();
    //void set_param_mac(pcap_t * pack_d);

};


//85 drink
#endif // PACKET_INFO_H
