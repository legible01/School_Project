#ifndef PRINTDATA_H
#define PRINTDATA_H
#include <cstdint>
#include <array>
#include <map>

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
    typedef array<uint8_t,6>bssid;
    typedef map<bssid,ap_data>print_ap_data;
    printdata();
    void get_ap_bssid();
    void get_ap_beacon();
    void get_ap_dpack();
    void get_ap_channel();
    void get_ap_encrypt();
    void get_ap_cipher();
    void get_ap_auth();
    void get_ap_ssid();



};

#endif // PRINTDATA_H
