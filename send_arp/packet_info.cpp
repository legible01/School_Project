#include "packet_info.h"
#include <stdint.h>
#include <cstdio>
#include <cstring>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <cstring>

packet_info ::packet_info()
{

}
//void get_my_info(char * dev_name ,uint32_t *struc_p,u_int8_t *struc_mac)
using namespace std;
packet_info :: operator=(string *argument)
{
    if(argument.find(".") != 0){
        set_argu_ip(argument)
    }else{
        this->dev_name =argument;

    }

}
void packet_info :: set_my_ip()
{

        struct ifreq ifr;
        strcpy(ifr.ifr_name, dev_name);

        int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (fd < 0) {
            printf("socket error\n");
            return ;
        }

        int result = ioctl(fd, SIOCGIFADDR, &ifr);
        check_ioctl_err(result);
        memcpy(this->my_ip,ifr.ifr_addr.sa_data+2,sizeof(uint32_t));// Get IP Adress

        result = ioctl(fd, SIOCGIFHWADDR, &ifr);
        check_ioctl_err(result);
        memcpy(this->my_mac,ifr.ifr_hwaddr.sa_data,sizeof(u_char)*6);//get mac addr



}

void packet_info ::check_ioctl_err(int ioctl_flag)
{
        if (ioctl_flag < 0){
            printf("getHardInfo Error");
            exit(1);
        }
        return;
}


