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
//=============ap_print===========

    typedef struct
    {
        uint beacons;
        uint data_pack;



    }ap_regen;

    typedef struct
    {
       ap_regen regen_data;
       uint channel;
       string encrypt;
       string cipher;
       string auth;
       string ssid;
       void get_channel(uint recv_channel)
       {
            channel = recv_channel;
       }
       void get_cipher(string recv_cipher)
       {
            cipher = recv_cipher;
       }
       void get_auth(string recv_auth)
       {
            auth = recv_auth;
       }
       void get_ssid(uint8_t* recv_ssid,int recv_ssid_length)
       {
           printf("ssid len :%d\n",recv_ssid_length);
           ssid.resize(recv_ssid_length);
           memcpy(&ssid[0],recv_ssid,recv_ssid_length);
           //cout<<(string)ssid<<endl;
       }

       void get_encrypt(string recv_encrypt)
       {
            encrypt = recv_encrypt;
       }
       void print_data_pack()
       {
           cout << regen_data.data_pack<<"\t";
       }
       void print_beacon()
       {
           cout << regen_data.beacons<<"\t";
       }

       void incr_beacon(uint recv_beacon)
       {
           //regen_data.beacons =0;
           (regen_data.beacons)+=recv_beacon;

       }
       void incr_data_pack(uint recv_d_pack)
       {

           //regen_data.data_pack =0;
           (regen_data.data_pack)+=recv_d_pack;
       }


    }ap_data;

    struct bssid
    {
        uint8_t mac_arr[6];
        bool operator<(const bssid s_mac)   const{
           return std::tie(mac_arr[0],mac_arr[1],mac_arr[2],mac_arr[3],mac_arr[4],mac_arr[5])<std::tie(s_mac.mac_arr[0],s_mac.mac_arr[1],s_mac.mac_arr[2],s_mac.mac_arr[3],s_mac.mac_arr[4],s_mac.mac_arr[5]);
        }
       /*bool operator<(const bssid* s_mac)   const{
           return std::tie(mac_arr[0],mac_arr[1],mac_arr[2],mac_arr[3],mac_arr[4],mac_arr[5])<std::tie(s_mac->mac_arr[0],s_mac->mac_arr[1],s_mac->mac_arr[2],s_mac->mac_arr[3],s_mac->mac_arr[4],s_mac->mac_arr[5]);
        }*/
       void print_mac(){
           for(int i=0;i<6;i++){
               printf("%02x ",this->mac_arr[i]);
           }
        printf("\t");
       }
    }__attribute__((packed)) typedef bssid;

    typedef map<bssid,ap_data>print_ap_data;
    print_ap_data  ap_data1;
    bssid recv_bssid;
    ap_data ap_value;

//=============station_print===========

    typedef struct
    {
        uint frames;
    }st_regen;
    typedef struct
    {
        st_regen regen_data;
        string probe;

        void incr_frame(uint recv_frame)
        {
            regen_data.frames += recv_frame;
        }
        void get_probe(uint8_t* recv_probe,int recv_probe_length)
        {
            //printf("probe len :%d\n",recv_probe_length);
            probe.resize(recv_probe_length);
            memcpy(&probe[0],recv_probe,recv_probe_length);
            //cout<<(string)ssid<<endl;
        }
        void print_frame()
        {
            cout << regen_data.frames<<"\t";
        }

    }st_data;




       struct station
       {
           uint8_t mac_arr[6];
           bool operator<(const station s_mac)   const{
              return std::tie(mac_arr[0],mac_arr[1],mac_arr[2],mac_arr[3],mac_arr[4],mac_arr[5])<std::tie(s_mac.mac_arr[0],s_mac.mac_arr[1],s_mac.mac_arr[2],s_mac.mac_arr[3],s_mac.mac_arr[4],s_mac.mac_arr[5]);
           }
          /*bool operator<(const bssid* s_mac)   const{
              return std::tie(mac_arr[0],mac_arr[1],mac_arr[2],mac_arr[3],mac_arr[4],mac_arr[5])<std::tie(s_mac->mac_arr[0],s_mac->mac_arr[1],s_mac->mac_arr[2],s_mac->mac_arr[3],s_mac->mac_arr[4],s_mac->mac_arr[5]);
           }*/
          void print_mac(){
              for(int i=0;i<6;i++){
                  printf("%02x ",this->mac_arr[i]);
              }
           printf("\t");
          }


    }__attribute__((packed)) typedef station;


       typedef map<pair<bssid,station>,st_data>print_st_data;
       print_st_data  st_data1;
       station recv_station;
       st_data st_value;
       void get_st_regen(bssid* recv_bssid_addr,station* recv_station_addr,uint recv_frame);
       //bssid

   void insert_new_map();

    printdata();
    ~printdata();
    bool chk_bssid(bssid* recv_bssid_addr);
    bool chk_station(bssid* recv_bssid_addr,station* recv_station_addr);
    void get_ap_regen(bssid* recv_bssid_addr,uint recv_beacon,uint recv_datapack);
    void get_ap_newmap(bssid* recv_bssid_addr);


   ap_data& pass_ap_data();
   st_data& pass_st_data();

   void print_cmd_ap();
   void data_zero_init();

   void get_st_newmap(bssid* recv_bssid_addr,station* recv_station_addr);



};

#endif // PRINTDATA_H
