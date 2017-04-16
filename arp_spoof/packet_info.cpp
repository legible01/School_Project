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
void packet_info :: allocate_param_ip_mem(int p_count,char *p_ip)//:param_count(0)
{
    param_count = p_count;
    sender_mac = new uint8_t*[param_count];
    target_mac = new uint8_t*[param_count];
    for(int i =0;i<param_count;++i){
        sender_mac[i] = new uint8_t[6];//must make delete heap memory
        target_mac[i] = new uint8_t[6];//= new uint32_t[param_count][6];
    }
    //6 size of mac + argument number
    sender_ip = new uint32_t[param_count];
    target_ip = new uint32_t[param_count];//save data with pton.

}

packet_info ::packet_info(char *_consol_dev,char *_consol_sender_ip,char *_consol_target_ip)
{
    dev_name=_consol_dev;
    inet_pton(AF_INET,_consol_sender_ip,&sender_ip);
    inet_pton(AF_INET,_consol_target_ip,&target_ip);
}

bool pack_info :: set_param(int argc,char *argv[])
{
    printf("argc : %d \n",argc)
}
int packet_info :: arp_iph_size(){
    int size_h;
    printf("%d",arp_iph.src_ip);
    size_h = sizeof(arp_iph);

    return 0;
}
