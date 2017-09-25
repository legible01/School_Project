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

    memset(dummy_mac,0xff,sizeof dummy_mac);
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
        ds_type = get_ds_type();
        get_802mac_addr(ds_type);
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
            memcpy(station,&mac802_comm->m802_addr2,6);
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

void mac80211::get_station_cntdata()
{
    //

//    pack_subtype = mac802_comm->m802_fc.subtype;//0:management,1:control,2:data
  //  pack_type = mac802_comm->m802_fc.type;

    //printf("check pack_type :%d\n",pack_type);
  //  printf("check sub pack_type :%d\n",pack_subtype);
    switch(pack_type){
    case 0:
        st_datas.get_notst_data();
        switch (pack_subtype) {
        case 4:
            get_probe_data();
            break;
        default:
            break;
        }
        break;
    case 1:
        st_datas.get_notst_data();
        break;
    case 2://<here1>filiter with ds_type,fffff bssid
         switch(ds_type){
         case 1:
             st_datas.get_incr_frame();
             break;
         case 3:
             if(memcmp(bssid,dummy_mac,sizeof(bssid))==0)
                st_datas.get_incr_frame();
             break;

         default:
             st_datas.get_notst_data();
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
        case 4:
            //get_probe_data();
            break;

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
        case 4:
            //01 2

        case 8:
            //get_qos_data();
            ap_datas.get_incr_data();

            break;
        default:
            ap_datas.get_notap_data();
        }

    }

}
void mac80211::get_probe_data()
{

    //if(memcmp(bssid,dummy_mac,sizeof(bssid))==0)
  //  {
        //nonedata

   // }
    int tag_data_len = packet_len - (rth_length+sizeof(mgmt_frame_hdr)+sizeof(beacon_frame_common)+sizeof(fcs));
    element_common * tag_entry = (element_common*)((uint8_t*)mac802_comm+sizeof(beacon_frame_common));
    //probe ssid use mgmt hdr
    while(tag_data_len > 0){
        if(tag_entry->element_id == 0){
            ssid_param* probe_tag = (ssid_param*)tag_entry;//herenow
            (st_datas.probe).resize(probe_tag->ssid_comm.element_leng+1,0);
            memcpy(&st_datas.probe[0],probe_tag->ssid,probe_tag->ssid_comm.element_leng);
            break;
        }
        else{
            tag_entry=(element_common *)((uint8_t*)tag_entry +(sizeof(element_common) + tag_entry->element_leng));
            tag_data_len-= (sizeof(element_common) + tag_entry->element_leng);

        }
    }
}
void mac80211::get_station_data()
{

    switch (pack_type) {
    case 0://mgmt
        switch (pack_subtype) {
        case 4:
            get_probe_data();
            break;
        default:
            st_datas.get_notst_data();
            break;
        }
        break;

    case 1://control
        st_datas.get_notst_data();
        break;

    case 2://data
        switch (pack_subtype) {
        case 0://data
           //get_data_data();
            st_datas.get_incr_frame();
            break;
        case 4:
            //01 2

        case 8:
            //get_qos_data();
            st_datas.get_incr_frame();

            break;
        default:
            st_datas.get_notst_data();
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

    //00:bss,:from,10:to,11:bridge
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

uint8_t* mac80211::pass_st_station()
{
    return station;
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
mac80211::st_data& mac80211:: pass_st_value()

{
    return st_datas;
}
uint mac80211:: pass_st_frame()
{
    return st_datas.pass_frame();
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


    int tag_data_len = packet_len - (rth_length+sizeof(mgmt_frame_hdr)+sizeof(beacon_frame_common)+sizeof(fcs));

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

    ssid_param* ssid_entry = (ssid_param*)tag_entry;
    (ap_datas.ssid).resize(ssid_entry->ssid_comm.element_leng+1,0);
    memcpy(&ap_datas.ssid[0],ssid_entry->ssid,ssid_entry->ssid_comm.element_leng);

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



       authentication_map_iter auth_iter =  auth_map.find(basic_rsn->asl.auth_type);//psk
        if (auth_iter != auth_map.end())
            ap_datas.auth=auth_iter->second;


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

}


//======================================================




void mac80211::data_init_zero()
{
    ap_regens = {};
    ap_datas = {};
    ds_type = 0;

    pack_subtype = 0;
    pack_type = 0;
    packet_len = 0;
}



