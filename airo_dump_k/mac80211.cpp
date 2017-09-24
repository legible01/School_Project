#include "mac80211.h"
#include <iostream>
#include <vector>
#include "radiotap.h"
#include <cstdint>
#include <map>
#include <cstring>



mac80211::mac80211()
{



    cipher_map[0] ="    ";
    cipher_map[1] ="WEP40";
    cipher_map[2] ="TKIP";
    cipher_map[3] ="RESV";
    cipher_map[4] ="CCMP";
    cipher_map[5] ="WEP104";


    auth_map[1]="PMK";
    auth_map[2]="PSK";

    enc_map[1]="WPA";
    enc_map[2]="WPA2";
    enc_map[4]="WPS";
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
    //printf("length: %d\n",rt_header->rth_leng);
}//set rth_length


void mac80211::get_common_data(uint8_t* pack_front,uint32_t pack_len)
{
    packet_len = pack_len;
    mac802_comm = (mac802_common_hdr *)((uint8_t*)pack_front + rth_length);
    pack_type = mac802_comm->m802_fc.type;//0:management,1:control,2:data
    pack_subtype = mac802_comm->m802_fc.subtype;
   // printf("type: %d\n",pack_type);
    //printf("subtype: %d\n",pack_subtype);

   // for(int a=0;a<6;a++){
   //     printf("%02x ",bssid[a]);
    //}
    //printf("\n");
    //mac802_comm = (mac802_common_hdr *)mac802_hdr_addr;
    if(pack_type != 1){
        //pack_ds_type = get_ds_type();
        get_802mac_addr(get_ds_type());
    }

}
void mac80211::get_802mac_addr(int ds_type)
{
    //printf("ds_type : %d\n",ds_type);
    switch (ds_type) {
    //define bssid position
    //easy to understand with https://networkengineering.stackexchange.com/questions/25100/four-layer-2-addresses-in-802-11-frame-header
        case 1://10
            memcpy(bssid,&mac802_comm->m802_addr1,6);
            memcpy(station,&mac802_comm->m802_addr2,6);
                    //memcpy(&recv_bssid,recv_bssid_addr,6);

            break;
        case 2://01
            memcpy(bssid,&mac802_comm->m802_addr2,6);
            memcpy(station,&mac802_comm->m802_addr3,6);
            break;
        case 3://00
            memcpy(bssid,&mac802_comm->m802_addr3,6);

            break;
        case 4://use ap <->ap (WDS frame),00

            break;
        default:
            break;
    }

}
void mac80211::get_mac802_cntdata()
{
    //

//    pack_subtype = mac802_comm->m802_fc.subtype;//0:management,1:control,2:data
  //  pack_type = mac802_comm->m802_fc.type;

    //printf("check pack_type :%d\n",pack_type);
  //  printf("check sub pack_type :%d\n",pack_subtype);
    switch(pack_type){
    case 0:
        switch(pack_subtype){
        case 8:
            ap_datas.get_incr_beacon();
            break;
        default:
            ap_datas.get_notap_data();
            break;
        }
        break;
    case 1:
        ap_datas.get_notap_data();
        break;
    case 2:
         switch(pack_subtype){
         case 0:
         case 8:
             ap_datas.get_incr_data();
             break;
         default:
             ap_datas.get_notap_data();
             break;
         }
         break;
    }
}

void mac80211::get_mac802_data()
{

    switch (pack_type) {
    case 0://mgmt
        get_mgmt_data();
        switch (pack_subtype) {
        case 8://sub_beacon
            get_beacon_data();
            break;
        default:
            ap_datas.get_notap_data();
            break;
        }
        //write_data();
        break;

    case 1://control
        ap_datas.get_notap_data();
        break;

    case 2://data
        switch (pack_subtype) {
        case 0://data
           //get_data_data();
            ap_datas.get_incr_data();
            break;
        case 8:
            //get_qos_data();
            ap_datas.get_incr_data();
            break;
        default:
            ap_datas.get_notap_data();
        }

    }

}
int mac80211::get_ds_type()
{
    //mac802_common_hdr * mac802_comm = (mac802_common_hdr *)mac802_hdr_addr;

    bool check1= (mac802_comm->m802_fc.to_ds)==(mac802_comm->m802_fc.from_ds);//00,11
    //printf(check1 ? "true" : "false");//2
    bool check2 =(mac802_comm->m802_fc.to_ds) == 1;//10,11
    //printf(check2 ? "true" : "false");

    switch (check1) {
        case true:
            switch (check2) {
                case true:
                return 4;//almost useless
                case false:
                return 3;
            }
        case false:
            switch (check2) {
                case true:
                return 1;
                case false:
                return 2;
                }
    }
}


void mac80211::get_mgmt_data()
{
}

    //00:bss,01:from,10:to,11:bridge
   // if((mac802_comm->m802_fc.to_from_ds) == 0){
     //   memcpy(ap_bssid,mac802_comm->m802_source,sizeof(ap_bssid));
        //for(int i=0;i<6;i++){
           // printf("\tdata: %02x\n",ap_bssid[i]);
        //}
     //else

    //}


/*int mac80211::pass_ap_dstype()
{
    return pack_ds_type;
}*/

uint8_t* mac80211::pass_ap_bssid()
{
    return bssid;
}

uint mac80211:: pass_ap_regen_beacon()

{
    return ap_datas.pass_beacon();
}
uint mac80211:: pass_ap_regen_data()

{
    return ap_datas.pass_data_pack();
}
mac80211::ap_data& mac80211:: pass_ap_value()

{
    return ap_datas;
}
void mac80211::get_beacon_data()
{
    ap_datas.get_incr_beacon();
    get_enc_data();

}
void mac80211::get_enc_data()
{
    //tag_common_info = mgmt_hdr_length+becon_mandatory_12_byte
    element_common * tag_entry = (element_common*)((uint8_t*)mac802_comm+sizeof(mgmt_frame_hdr)+sizeof(beacon_frame_common));


    //uint8_t * t1 = (uint8_t*)tag_entry;
    //printf("mac position : %02x %02x %02x \n" ,*(uint8_t*)t1,*(uint8_t*)(t1+1),*(uint8_t*)(t1+2));
    int tag_data_len = packet_len - (rth_length+sizeof(mgmt_frame_hdr)+sizeof(beacon_frame_common)+sizeof(fcs));
    //printf("tag len : %d\n",tag_data_len);
    bool check_opn = true;
    while(tag_data_len > 0){
        switch (tag_entry->element_id) {
            case 0://ssid
                get_ssid(tag_entry);
                break;
            case 3://cypher,auth
                get_current_ch(tag_entry);
                break;
            case 48://cypher,auth
                check_opn = false;
                get_cypher_auth(tag_entry);
                break;
            case 221://wpa,wpa2
                get_enc(tag_entry);
                break;
            default:
                break;
        }
        tag_data_len -=((tag_entry->element_leng)+sizeof(element_common));
        tag_entry = (element_common *)((uint8_t*)tag_entry + (sizeof(element_common)+(tag_entry->element_leng)));

    }
    if(check_opn == true){
            ap_datas.encrpt = "OPN";
            ap_datas.cipher="";
            ap_datas.auth="";
    }
}

void mac80211::get_ssid(element_common* tag_entry)
{
   // printf("size of ssid %d",sizeof(ap_datas.ssid));

    ssid_param* ssid_entry = (ssid_param*)tag_entry;
    (ap_datas.ssid).resize(ssid_entry->ssid_comm.element_leng+1,0);
    memcpy(&ap_datas.ssid[0],ssid_entry->ssid,ssid_entry->ssid_comm.element_leng);
    //printf("size of ssid %d\n\n",sizeof(ssid_entry->ssid_comm.element_leng));

    //for (str_data::iterator i = (ap_datas.ssid).begin(); i != (ap_datas.ssid).end(); ++i)
      // std::cout << *i;
       // printf("\n");
}



void mac80211::get_current_ch(element_common* tag_entry)
{
    channel_param* ch_entry = (channel_param*)tag_entry;
    ap_datas.channel = ch_entry->channel;
}
void mac80211::get_cypher_auth(element_common* tag_entry)
{
    rsn_common_info* rsn_entry = (rsn_common_info*)tag_entry;
    if(rsn_entry->rsn_com.element_leng == 20){
        tag_rsn_info* basic_rsn = (tag_rsn_info*)rsn_entry;

        cip_map_iter cip_iter = cipher_map.find(basic_rsn->psl.pair_type);
        if (cip_iter != cipher_map.end())
            ap_datas.cipher=cip_iter->second;
         //   cout << "cipher에 매핑된 value : " << cip_iter->second << endl;}


       authentication_map_iter auth_iter =  auth_map.find(basic_rsn->asl.auth_type);//psk
        if (auth_iter != auth_map.end())
            ap_datas.auth=auth_iter->second;
           // cout << "auth에 매핑된 value : " << ap_datas.auth<< endl;}

    }else{
        int p_cnt =rsn_entry->psc;
        pair_suite_list* psl_entry=(pair_suite_list*)((uint8_t*)rsn_entry+sizeof(rsn_common_info));

        while(p_cnt!=0)
        {
            cip_map_iter cip_iter = cipher_map.find(psl_entry->pair_type);
            if (cip_iter != cipher_map.end())
                ap_datas.cipher=cip_iter->second;
             p_cnt-=1;
             psl_entry = (pair_suite_list*)((uint8_t*)psl_entry+sizeof(pair_suite_list));
        }
        uint16_t* asc_entry = (uint16_t*)psl_entry;
        int a_cnt = *asc_entry;
        auth_suite_list* asl_entry = (auth_suite_list*)((uint8_t*)asc_entry+sizeof(*asc_entry));
        while(a_cnt!=0)
        {
            authentication_map_iter auth_iter =  auth_map.find(asl_entry->auth_type);//psk
             if (auth_iter != auth_map.end())
                 ap_datas.auth=auth_iter->second;
             a_cnt-=1;
             asl_entry = (auth_suite_list*)((uint8_t*)asl_entry+sizeof(auth_suite_list));

        }

    }
}

void mac80211::get_enc(element_common* tag_entry)
{
    tag_encrypt_info* enc_entry = (tag_encrypt_info*) tag_entry;
    encrypt_map_iter enc_iter = enc_map.find(enc_entry->enc_type);
    if (enc_iter != enc_map.end())
        ap_datas.encrpt=enc_iter->second;

        //cout << "enc에 매핑된 value : " << ap_datas.encrpt<< endl;}
}


void mac80211::data_init_zero()
{
    ap_regens = {};
    ap_datas = {};

    pack_subtype = 0;
    pack_type = 0;
    packet_len = 0;
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

/*oid mac80211::edit_apdata1_map(int data)
{
    int test;



    if(test == true){

    return ;
}
*/
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
