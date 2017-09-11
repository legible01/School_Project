#include "mac80211.h"
#include <iostream>
#include <vector>
#include "radiotap.h"
#include <cstdint>
#include <map>
#include <cstring>



mac80211::mac80211()
{

    cip_map cipher_map;//int,string
    cipher_map[0] ="    ";
    cipher_map[1] ="WEP-40";
    cipher_map[2] ="TKIP";
    cipher_map[3] ="RESV";
    cipher_map[4] ="CCMP";
    cipher_map[5] ="WEP-104";

    authentication_map auth_map;//int,string
    auth_map[1]="PMK";
    auth_map[2]="PSK";
}

void mac80211::find_enc()
{
    //start addr frame var
    //if not service set identity(ssid)
    //if not 48(rsn)

}

void mac80211::get_rth_leng(uint8_t* pack_front)
{
    radiotap::rt_common_hdr * rt_header= (radiotap::rt_common_hdr *)pack_front;
    rth_length = rt_header->rth_leng;
    printf("length: %d\n",rt_header->rth_leng);
}//set rth_length

u_char* mac80211::get_802mac_type(u_char *pack_front)
{
    mac802_hdr_addr = pack_front + rth_length;

    //check type (vector<uint8_t>::iterator mac802_types_iter;)
    mac802_common_hdr * mac802_comm = (mac802_common_hdr *)mac802_hdr_addr;
    pack_subtype = mac802_comm->m802_fc.subtype;//0:management,1:control,2:data
    pack_type = mac802_comm->m802_fc.type;



}
void mac80211::get_802mac_data()
{
    switch (pack_type) {
    case 0://mgmt
        get_mgmt_data();
        switch (pack_subtype) {
        case 8:
           // get_beacon_data();
            break;
        }
        //write_data();
        break;

    case 1://control
        printf("");
        break;

    case 2://data
        printf("");
        break;
    }
}

void mac80211::get_mgmt_data()
{
    mac802_common_hdr * mac802_comm = (mac802_common_hdr *)mac802_hdr_addr;
    //00:bss,01:from,10:to,11:bridge
    if((mac802_comm->m802_fc.to_from_ds) == 0){
        memcpy(ap_bssid,mac802_comm->m802_source,sizeof(ap_bssid));
        for(int i=0;i<6;i++){
            printf("\tdata: %02x\n",ap_bssid[i]);
        }
     //else

    }
}


    //chk_sub_type = mac802_hdr_fc->fc_types;
   // chk_sub_type &= 240;//11110000
   // chk_sub_type >>= 4;

   // printf("type: %d    sub:%d\n", chk_type,chk_sub_type);
    //for(m_type_iter = mac802_types.begin();m_type_iter != mac802_types.end();m_type_iter++)
   // {
    //     if(m_type_iter)
    //}

  // radio_tap_header *rth = (radio_tap_header *)pack_front;

//get entry point(address)with rth(change after )

void mac80211::edit_apdata1_map(int data)
{
    int test;



    if(test == true){
    //ap_data1_map.insert(pair<int,struct ap_data>(1,{"",0,0,0,0,0,0,"","","",""}));
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
    //ap_data1_map.ap
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
