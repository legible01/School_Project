#include "packet_info.h"
#include <stdint.h>
#include <cstdio>
#include <cstring>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <cstring>
#include <arpa/inet.h>
#include <net/if.h>

packet_info ::packet_info(char *_consol_dev,char *_consol_sender_ip,char *_consol_target_ip)
{
    dev_name=_consol_dev;
    inet_pton(AF_INET,_consol_sender_ip,&sender_ip);
    inet_pton(AF_INET,_consol_target_ip,&target_ip);
}
//void get_my_info(char * dev_name ,uint32_t *struc_p,u_int8_t *struc_mac)
/*using namespace std;

packet_info& packet_info :: operator=(char *argument)
{
    switch(this->argu_check){
        case 0:
            printf("archeck: %d\n",this->argu_check);
            this->dev_name = argument;
            (this->argu_check)++;
            return *this;
        case 1:
            printf("archeck: %d\n",this->argu_check);
            inet_pton(AF_INET,argument,&(this->sender_ip));
            (this->argu_check)++;
            return *this;
        case 2:
            printf("archeck: %d\n",this->argu_check);
            inet_pton(AF_INET,argument,&(this->target_ip));
            return *this;


    }

}*/
void packet_info :: printData()
{
    //printf("archeck: %d\n",this->argu_check);
    for(int i=0;i<4;i++)
        printf("%c",this->dev_name[i]);
    printf("\n");
    printf("\n%x\n",this->sender_ip);
    printf("\n");
    printf("\nmy ip:%x\n",this->my_ip);
    printf("\nsender ip:%x\n",this->sender_ip);
    for(int j=0;j<4;j++)
        printf(" %02x ",this->sender_mac[j]);
    //printf("\n%x\n",this->sender_ip);

}


void packet_info :: set_my_ip_mac()
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
        memcpy(&this->my_ip,ifr.ifr_addr.sa_data+2,sizeof(uint32_t));// Get IP Adress

        result = ioctl(fd, SIOCGIFHWADDR, &ifr);
        check_ioctl_err(result);
        memcpy(&this->my_mac,ifr.ifr_hwaddr.sa_data,sizeof(uint8_t)*6);//get mac addr



}
char* packet_info ::get_info_dev(){

    return this->dev_name;
}
uint8_t& packet_info::get_info_my_mac(){

    return this->my_mac[0];
}
uint8_t& packet_info::get_info_sender_mac(){

    return this->sender_mac[0];
}
uint8_t& packet_info::get_info_target_mac(){

    return this->target_mac[0];
}
uint32_t& packet_info::get_info_my_ip(){

    return this->my_ip;
}
uint32_t& packet_info::get_info_sender_ip(){

    return this->sender_ip;
}
uint32_t& packet_info::get_info_target_ip(){

    return this->target_ip;
}
void packet_info::set_info_sender_mac(uint8_t* mac_addr){
    memcpy(this->sender_mac,mac_addr,sizeof(uint8_t)*6);

}
void packet_info::set_info_target_mac(uint8_t* mac_addr){
    memcpy(this->target_mac,mac_addr,sizeof(uint8_t)*6);

}


void packet_info ::check_ioctl_err(int ioctl_flag)
{
        if (ioctl_flag < 0){
            printf("getHardInfo Error");
            return;
        }
        return;
}


