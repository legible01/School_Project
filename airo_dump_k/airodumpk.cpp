#include "airodumpk.h"
#include <iostream>
#include <vector>
using namespace std;

AiroDumpK::AiroDumpK()
{
    mac802_types.push_back(0);
    mac802_types.push_back(4);//
    mac802_types.push_back(2);//data
}

void AiroDumpK::get_rth_info(u_char *pack_front)
{
    struct radio_tap_header *rth = (struct radio_tap_header *)pack_front;
    rth_length = rth->rth_leng;//get length
    printf("length: %d\n",rth_length);
}//set rth_length


u_char* AiroDumpK::get_802mac_info(u_char *pack_front)
{
    mac802_hdr_addr = pack_front + rth_length;

    //check type (vector<uint8_t>::iterator mac802_types_iter;)
    struct m802_fc * mac802_hdr_fc = (struct m802_fc *)mac802_hdr_addr;
    uint8_t chk_type = mac802_hdr_fc->fc_types;
    chk_type &= 12;//00001100
    chk_type >>= 2;

    chk_sub_type = mac802_hdr_fc->fc_types;
    chk_sub_type &= 240;//11110000
    chk_sub_type >>= 4;

    printf("type: %d    sub:%d\n", chk_type,chk_sub_type);
    //for(m_type_iter = mac802_types.begin();m_type_iter != mac802_types.end();m_type_iter++)
    //{
    //     if(m_type_iter)
    //}

    struct radio_tap_header *rth = (struct radio_tap_header *)pack_front;

}//get entry point(address)with rth(change after )

void AiroDumpK::edit_apdata1_map(int data)
{
    int test;



    if(test == true){
    ap_data1_map.insert(pair<int,struct ap_data>(1,{"",0,0,0,0,0,0,"","","",""}));
       // ap_data1_map[1] = ;
    }
    /*

        string ap_data_bssid;
        int ap_data_pwr;
        int ap_data_beacon;
        int ap_data_data;
        int ap_data_s;
        int ap_data_ch;
        int ap_data_mb;
        string ap_data_enc;
        string ap_data_cipher;
        string ap_data_auth;
        string essid;
*/

    //ap_data1_map
    //iterator ap_data1_iter
    ap_data1_map.ap
    return ;
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
