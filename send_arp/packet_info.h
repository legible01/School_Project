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
    packet_info(char *_consol_dev,char *_consol_sender_ip,char *_consol_target_ip);
    void check_ioctl_err(int ioctl_flag);
    void set_my_ip_mac();
    char* get_info_dev();
    uint8_t& get_info_my_mac();
    uint8_t& get_info_sender_mac();
    uint8_t& get_info_target_mac();
    uint32_t& get_info_my_ip();
    uint32_t& get_info_sender_ip();
    uint32_t& get_info_target_ip();
    void set_info_sender_mac(uint8_t* mac_addr);
    void set_info_target_mac(uint8_t* mac_addr);


   // void set_my_dev(char * dev_argu);
    //void get_my_info(char * dev_name, uint32_t *struc_p, u_char *struc_mac);
   // void check_ioctl_err(int ioctl_flag);
   // packet_info& operator=(char* argument);   USELESS
    void printData();
};

#endif // PACKET_INFO_H
