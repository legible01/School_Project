#ifndef PACKET_INFO_H
#define PACKET_INFO_H
#include <stdint.h>


class packet_info
{
private:
    char *dev_name;
    uint32_t my_ip;
    uint32_t target_ip;
    uint32_t sender_ip;//pton use change
    uint8_t my_mac[6];
    uint8_t sender_mac[6];
    uint8_t target_mac[6];

public:
    packet_info();
    void set_my_dev(char * dev_argu);
    void get_my_info(char * dev_name, uint32_t *struc_p, u_char *struc_mac);
    void check_ioctl_err(int ioctl_flag);
};

#endif // PACKET_INFO_H
