#ifndef PRINTDATA_H
#define PRINTDATA_H
#include <iostream>
#include <cstdio>
#include <cstring>
#include <cstdint>
#include <vector>
#include <map>
#include <tuple>

using namespace std;

class printdata
{
public:
    int data_layer;

    typedef struct
    {

       uint beacons;
       uint data_pack;
       uint channel;
       string encrypt;
       string cipher;
       string auth;
       string ssid;
    }ap_data;

    struct bssid
    {
        uint8_t mac_arr[6];
        bool operator<(const bssid s_mac)   const{
           return std::tie(mac_arr[0],mac_arr[1],mac_arr[2],mac_arr[3],mac_arr[4],mac_arr[5])<std::tie(s_mac.mac_arr[0],s_mac.mac_arr[1],s_mac.mac_arr[2],s_mac.mac_arr[3],s_mac.mac_arr[4],s_mac.mac_arr[5]);
        }
       bool operator<(const bssid* s_mac)   const{
           return std::tie(mac_arr[0],mac_arr[1],mac_arr[2],mac_arr[3],mac_arr[4],mac_arr[5])<std::tie(s_mac->mac_arr[0],s_mac->mac_arr[1],s_mac->mac_arr[2],s_mac->mac_arr[3],s_mac->mac_arr[4],s_mac->mac_arr[5]);
        }
       void print_mac(){
           for(int i=0;i<6;i++){
               printf("%02x",this->mac_arr[i]);
           }

       }

    }__attribute__((packed)) typedef bssid;
    //typedef tuple<uint8_t,uint8_t,uint8_t,uint8_t,uint8_t,uint8_t> bssid;
    typedef map<bssid,ap_data>print_ap_data;
    print_ap_data*   ap_data1;
    bssid* recv_bssid;
    ap_data* ap_value;

   void insert_new_map();

    printdata();
    ~printdata();
    void get_ap_bssid(uint8_t* recv_bssid_addr);
    void get_ap_beacon();
    void get_ap_dpack();
    void get_ap_channel();
    void get_ap_encrypt();
    void get_ap_cipher();
    void get_ap_auth();
    void get_ap_ssid();



};

#endif // PRINTDATA_H
