#ifndef PACKET_INFO_H
#define PACKET_INFO_H
#include <stdint.h>
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

public:
    void allocate_param_mem(int p_count,char *param_dev);//var create
    void set_param_ip(char **param_ip);//param input
    void set_param_mac();
    void delete_param_mem();//var delete
    void set_my_info();
    void check_ioctl_err(int ioctl_flag);
    void set_param_ip();
    char* get_my_dev();
    void set_param_mac(pcap_t * pack_d);
    void arp_req_common_set(struct libnet_ethernet_hdr* pack_req_buf);
};


//85 drink
#endif // PACKET_INFO_H
