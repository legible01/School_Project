#ifndef MAC80211_H
#define MAC80211_H

#include <iostream>
#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <string>
#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <vector>
#include <map>
#include "radiotap.h"
#include <tuple>


using namespace std;



class mac80211
{
public:
    //other hdr's info
    int rth_length;//radiotaplength

    //mac802_common_hdr * mac802_comm;//
    //uint8_t chk_sub_type ;

    //data for filter
    uint8_t pack_subtype;
    uint8_t pack_type;
    uint32_t packet_len;
    bool cmp_bs_st;
    //int pack_ds_type;


    //data for print ap
    uint8_t bssid[6];
    uint8_t station[6];

    struct{
        uint beacons;
        uint data_pack;
        void incr_re_becon(){
            beacons =1;
            data_pack =0;
        }
        void incr_re_data(){
            data_pack =1;
            beacons =0;
        }
    }typedef ap_regen;

    ap_regen ap_regens;
    typedef std::vector<uint8_t> str_data;
    typedef struct{
        ap_regen regen;
        int channel;
        string encrpt;
        string cipher;
        string auth;
        str_data ssid;
        int ssid_len(){
            return ssid.size();
        }
        uint pass_beacon()
        {
            return regen.beacons;
        }
        uint pass_data_pack()
        {
            return regen.data_pack;
        }
        void get_incr_beacon()
        {
         regen.beacons = 1;
         regen.data_pack =0;
        }
        void get_incr_data()
        {
         regen.beacons = 0;
         regen.data_pack =1;
        }
        void get_notap_data()
        {
         regen.beacons = 0;
         regen.data_pack =0;
        }
     } ap_data;

    ap_data ap_datas;
    //ap_regen re_ap_data;

    //map enc
    typedef std::map<int,std::string> cip_map;
    cip_map cipher_map;//int,string
    typedef std::map<int,std::string>::iterator cip_map_iter;

    typedef std::map<int,std::string> authentication_map;
    authentication_map auth_map;//int,string
    typedef std::map<int,std::string>::iterator authentication_map_iter;

    typedef std::map<int,std::string> encrypt_map;
    encrypt_map enc_map;//int,string
    typedef std::map<int,std::string>::iterator encrypt_map_iter;



    void get_rth_leng(uint8_t* pack_front);

    //common mac set
    typedef struct
    {
        uint8_t proc_ver:2;
        uint8_t type:2;
        uint8_t subtype:4;
        uint8_t to_ds:1;
        uint8_t from_ds:1;
        uint8_t more_flag:1;
        uint8_t retry:1;
        uint8_t pow_mgmt:1;
        uint8_t more_data:1;
        uint8_t wep:1;
        uint8_t rsvd:1;
    }__attribute__((packed)) fc;

    typedef struct
    {
        fc m802_fc;
        uint16_t m802_dur;
        uint8_t m802_addr1[6];
        uint8_t m802_addr2[6];
        uint8_t m802_addr3[6];
        uint16_t m802_seq;
    }__attribute__((packed)) mac802_common_hdr;//after this beacon packet. need compare length and find string
    uint32_t fcs;
    mac802_common_hdr* mac802_comm;//start addr

    //===================for tag search struct(beacon)==================
    typedef struct
    {
      mac802_common_hdr mac_com_hdr;
      uint8_t m802_addr4[6];
      uint16_t qos_control;
      uint32_t ht_control;
    }__attribute__((packed)) data_frame_hdr;

    typedef struct
    {

      mac802_common_hdr mac_common_hdr;

    }__attribute__((packed)) mgmt_frame_hdr;






    typedef struct
    {
      uint32_t  timestamp[2];
      uint16_t beacon_interval;
      uint16_t capa_info;

    }__attribute__((packed)) beacon_frame_common;
    typedef struct
    {
        uint8_t element_id;
        uint8_t element_leng;
    }__attribute__((packed)) element_common;


    typedef struct
    {
        element_common ssid_comm;
        uint8_t ssid[32];
    }__attribute__((packed)) ssid_param;
    typedef struct
    {
        element_common channel_comm;
        uint8_t channel;
    }__attribute__((packed)) channel_param;
    //---------------------------------------------------
    //============== psk tag (beacon)================================

    typedef struct{//auth_suite_list(count*4bytes)
        uint8_t group_oui[3];
        uint8_t group_type;
    }__attribute__((packed)) group_suite_list;
    typedef struct{//pair_suite_list(count*4bytes)
        uint8_t pair_oui[3];
        uint8_t pair_type;
    }__attribute__((packed)) pair_suite_list;

    typedef struct{//auth_suite_list(count*4bytes)
        uint8_t auth_oui[3];
        uint8_t auth_type;
    }__attribute__((packed)) auth_suite_list;
    typedef struct
    {
        element_common rsn_com;
        uint16_t ver;//version
        group_suite_list gsl;//group_key_suite_oui
        uint16_t psc;//pair_suite_count
    }__attribute__((packed)) rsn_common_info;

    typedef struct
    {
        rsn_common_info rci;
        pair_suite_list psl;//pair_suite_list(count*4bytes)
        uint16_t asc;//Auth_suite_count
        auth_suite_list asl;//auth_suite_list(count*4bytes)
        int16_t capa;//capabilities


    }__attribute__((packed)) tag_rsn_info;


    typedef struct
    {
        element_common enc_com;
        uint8_t enc_oui[3];
        uint8_t enc_type;//1,2,4(wps)
        uint8_t enc_ver[5];



    }__attribute__((packed)) tag_encrypt_info;

    //----------------------------------------------

    //======================beacon_packet====================
    typedef struct
    {
        mac802_common_hdr mac_hdr_comm;
        beacon_frame_common beacon_comm;
    }__attribute__((packed)) beacon_mgmt;

    //-------------------------------------------------

    void get_rth_info(uint8_t *pack_front);
    void get_common_data(uint8_t *pack_front,uint32_t pack_len);

    int get_ds_type();
    bool pass_cmp_bs_st();
    void cmp_bssid_destination(uint8_t* addr1,uint8_t* addr2);
    void get_mac802_cntdata();
    void get_802mac_addr(int ds_type);

    void get_station_cntdata();

    void get_ssid(element_common* tag_entry);
    void get_current_ch(element_common* tag_entry);
    void get_cypher_auth(element_common* tag_entry);
    void get_enc(element_common* tag_entry);
    void get_channel(element_common* tag_entry);

    void get_probe_data();


    //void edit_apdata1_map(int data);
    void get_mac802_data();
    void get_mgmt_data();
    void get_beacon_data();
    void get_enc_data();

    void get_data_data();
    void get_qos_data();

    //void set_struct();





    //send data printdata_file
    int pass_ap_dstype();
    uint8_t* pass_ap_bssid();

    uint8_t* pass_st_station();
    uint pass_ap_regen_beacon();
    uint pass_ap_regen_data();
    uint pass_st_frame();
    ap_data& pass_ap_value();

    void data_init_zero();
    //void set_ap_regeninfo();
    //void set_ap_allinfo();


    mac80211();

    //================
    int ds_type;

    struct{
        uint frames;
    }typedef st_regen;
    typedef struct{
        st_regen regen;

        str_data probe;
        int probe_len(){
            return probe.size();
        }
        uint pass_frame()
        {
            return regen.frames;
        }

        void get_incr_frame()
        {
         regen.frames= 1;

        }

        void get_notst_data()
        {
         regen.frames = 0;
        }
     } st_data;

    st_data st_datas;
    st_data& pass_st_value();
uint8_t dummy_mac[6];
};



#endif // MAC80211_H
