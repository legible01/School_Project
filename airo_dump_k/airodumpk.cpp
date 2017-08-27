#include "airodumpk.h"
#include <vector>

AiroDumpK::AiroDumpK()
{

}

int AiroDumpK::find_802macframe(u_char *pack_front)
{
    struct RadioTapHeader *rth = (struct RadioTapHeader *)pack_front;
    return rth->rth_leng;
}

/*
void packet_info ::  set_my_info()
{

    struct ifreq ifr;
    strcpy(ifr.ifr_name, dev_name);

    printf("\nname %s\n\n",dev_name);
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0) {
        printf("socket error\n");
        return ;
    }
    printf("\nfd value: %d",fd);
    int result = ioctl(fd, SIOCGIFADDR, &ifr);
    printf("vaulu:%d \n",result);
    check_ioctl_err(result);
    memcpy(&this->my_ip,ifr.ifr_addr.sa_data+2,sizeof(uint32_t));// Get IP Adress
    printf("\nmyip: %02x\n",my_ip);
    result = ioctl(fd, SIOCGIFHWADDR, &ifr);
    check_ioctl_err(result);
    memcpy(&this->my_mac,ifr.ifr_hwaddr.sa_data,sizeof(uint8_t)*6);//get mac addr
    for(int i=0;i<6;i++)
        printf("%02x",my_mac[i]);
}
*/
