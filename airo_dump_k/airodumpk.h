#ifndef AIRODUMPK_H
#define AIRODUMPK_H
#include <iostream>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <vector>
#include <list>
#include <map>

using namespace std;


class AiroDumpK
{
private:
    int rth_length;
    u_char* mac802_hdr_addr;
    uint8_t chk_sub_type ;

    enum
    {
        types_num = 3
    };
public:
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

    struct radio_tap_header{
       uint8_t rth_revision;
       uint8_t rth_pad;
       uint16_t rth_leng;
    }__attribute__((packed));//same as pragma(1)

    struct m802_fc{
    uint8_t fc_types;
    uint8_t fc_else;
    }__attribute__((packed));

    struct mac802_common_dr{
        struct m802_fc frame_control;
        uint16_t m802_dur;
        uint8_t m802_addr1[6];
        uint8_t m802_addr2[6];
        uint8_t m802_addr3[6];
        uint16_t m802_seq;
    }__attribute__((packed));

    struct mac802_management{
        uint16_t m802_fc;//framecontrol
        uint16_t m802_dur;
        uint8_t m802_addr1[6];
        uint8_t m802_addr2[6];
        uint8_t m802_addr3[6];
        uint16_t m802_seq;
    }__attribute__((packed));
    //int

    vector<uint8_t>mac802_types;//initialize
    vector<uint8_t>::iterator m_type_iter;
   // list<ap_data>data;
    map<int,struct ap_data> ap_data1_map;
    map<int,struct ap_data>::iterator ap_data1_iter;

    AiroDumpK();
    void get_rth_info(u_char *pack_front);
    u_char* get_802mac_info(u_char *pack_front);
    void edit_apdata1_map(int data);
    //int get_802mac_type(u_char *pack_front);
        /*void allocate_param(int p_count,char *param_dev);
        void set_param_ip(char **param_ip);//param input
        void set_param_mac(pcap_t * pack_d);
        void delete_param_mem();//var delete*/
};

#endif // AIRODUMPK_H
