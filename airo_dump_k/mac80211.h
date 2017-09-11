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

using namespace std;



class mac80211
{
private:
    //other hdr info
    int rth_length;//radiotaplength
    u_char* mac802_hdr_addr;//start addr
    uint8_t chk_sub_type ;

    //data for filter
    uint8_t pack_subtype;
    uint8_t pack_type;

    //data for print ap
    uint8_t ap_bssid[6];
    int ap_beacons;
    int ap_data;
    int ap_ch;
    string enc;
    string cipher;
    string ssid;

    //map enc
    typedef std::map<int,std::string> cip_map;
    typedef std::map<int,std::string>::iterator cip_map_iter;
    typedef std::map<int,std::string> authentication_map;
    typedef std::map<int,std::string>::iterator authentication_map_iter;




    //data for print station


    enum
    {
        types_num = 3
    };




    //for print
  /*
    struct ap_data
    {
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


    };
*/

public:
    void find_enc();
    void get_rth_leng(uint8_t* pack_front);
    //common mac set
    typedef struct
    {
        uint8_t proc_ver:2;
        uint8_t type:2;
        uint8_t subtype:4;
        uint8_t to_from_ds:2;
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
        uint8_t m802_source[6];
        uint16_t m802_seq;
    }__attribute__((packed)) mac802_common_hdr;




    //for search tag
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
        element_common ssid_com;
        uint8_t* ssid;
    }__attribute__((packed)) ssid_param;

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
        uint32_t gks;//group_key_suite
        uint16_t psc;//pair_suite_count
        uint8_t* psl[4];//pair_suite_list(count*4bytes)
        uint16_t asc;//Auth_suite_count
        uint8_t* asl[4];//auth_suite_list(count*4bytes)
        int16_t capa;//capabilities


    }__attribute__((packed)) tag_rsn_info;

    typedef struct
    {
        mac802_common_hdr mac_hdr_comm;
        beacon_frame_common beacon_comm;


    }__attribute__((packed)) beacon_mgmt;



    //beacon frame body


    //vector<uint8_t>mac802_types;//initialize
    //vector<uint8_t>::iterator m_type_iter;
   // list<ap_data>data;
   // map<int,struct ap_data> ap_data1_map;
    //map<int,struct ap_data>::iterator ap_data1_iter;

    void get_rth_info(u_char *pack_front);
    u_char* get_802mac_type(u_char *pack_front);
    void edit_apdata1_map(int data);
    void get_802mac_data();
    void get_mgmt_data();
    void set_ap_bssid();
    void set_ap_beacon();
    void set_ap_dpack();
    void set_ap_channel();
    void set_ap_encrypt();
    void set_ap_cipher();
    void set_ap_auth();
    void set_ap_ssid();
    //int get_802mac_type(u_char *pack_front);
        /*void allocate_param(int p_count,char *param_dev);
        void set_param_ip(char **param_ip);//param input
        void set_param_mac(pcap_t * pack_d);
        void delete_param_mem();//var delete*/
    mac80211();

};

#endif // MAC80211_H
