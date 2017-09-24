#include "printdata.h"
using namespace std;
printdata::printdata()
{
    ap_value.regen_data.beacons =0;
    ap_value.regen_data.data_pack =0;
    //ap_data1 = new print_ap_data;
    //recv_bssid = new bssid;
   // ap_value = new ap_data{0,0,0,"","","",""};


}
printdata::~printdata()
{
    //delete[] recv_bssid;
    //delete[] ap_data1;
    //delete[] ap_value;

}
//void printdata::pass_data(bssid& mac_info,ap_data& pack_info)
//{
    //recv_bssid = mac_info
    //ap_value = pack_info
//}

bool printdata::chk_bssid(bssid* recv_bssid_addr)
{


    //print_ap_data::iterator it;
    //it = ap_data1.count((bssid)*recv_bssid_addr);
    if(int a=ap_data1.count((bssid)*recv_bssid_addr) ){
        //printf("count %d\n",a);
        return false;
    }else
        return true;

}
void printdata::get_ap_regen(bssid* recv_bssid_addr,uint recv_beacon,uint recv_datapack)
{
    print_ap_data::iterator it;
    it = ap_data1.find((bssid)*recv_bssid_addr);
    if(it != ap_data1.end() ){

        ap_value = (ap_data)it->second;
        ap_value.incr_beacon(recv_beacon);
        ap_value.incr_data_pack(recv_datapack);
        it->second = ap_value;
    }


}



void printdata::get_ap_newmap(bssid* recv_bssid_addr)
{

    print_ap_data::iterator it;
    it = ap_data1.find((bssid)*recv_bssid_addr);
    if(it == ap_data1.end() ){

        //none data append new map
        memcpy(&recv_bssid,recv_bssid_addr,6);
        ap_data1.insert(print_ap_data::value_type(recv_bssid,ap_value));//none data insert


    }else{
        //if has data regen?
        for(it = ap_data1.begin(); it!= ap_data1.end();++it)
        {
            ((bssid)(it->first)).print_mac();
            //test->print_mac();
        }
    }
}

printdata::ap_data& printdata::pass_ap_data()
{

    return ap_value;
}

void printdata::print_cmd_ap()
{
    system("clear");
    string str1 ="BSSID\t            Beacons   #Data    CH       ENC     CIPHER   AUTH   ESSID\n";
    print_ap_data::iterator it;
    cout <<str1 <<endl;
    for(it = ap_data1.begin(); it!= ap_data1.end();++it)
    {
        ((bssid)(it->first)).print_mac();
        ((ap_data)(it->second)).print_beacon();
        ((ap_data)(it->second)).print_data_pack();

        cout << ((ap_data)(it->second)).channel<<"\t"<<((ap_data)(it->second)).encrypt<<"\t"<< ((ap_data)(it->second)).cipher<<"\t"<<((ap_data)(it->second)).auth<<"\t"<<((ap_data)(it->second)).ssid<<endl;

    }
    string str2 ="BSSID\t            STATION\t            FRAMES   PROBE\n";
    cout <<str2 <<endl;
}

void printdata::data_zero_init()
{
    ap_value = {};
    recv_bssid = {};
}

