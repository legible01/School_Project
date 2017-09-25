#include "printdata.h"
using namespace std;
printdata::printdata()
{
    ap_value.regen_data.beacons =0;
    ap_value.regen_data.data_pack =0;


}
printdata::~printdata()
{


}


bool printdata::chk_bssid(bssid* recv_bssid_addr)
{


    if(ap_data1.count((bssid)*recv_bssid_addr) ){
        //printf("count %d\n",a);
        return false;
    }else
        return true;

}
bool printdata::chk_station(bssid* recv_bssid_addr,station* recv_station_addr)
{



    if(st_data1.count(make_pair((bssid)*recv_bssid_addr,(station)*recv_station_addr)) ){
        //printf("count %d\n",a);
        return true;
    }else
        return false;

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
void printdata::get_st_regen(bssid* recv_bssid_addr,station* recv_station_addr,uint recv_frame)//here st
{
    print_st_data::iterator it;
    it = st_data1.find(make_pair((bssid)*recv_bssid_addr,(station)*recv_station_addr));
    if(it != st_data1.end() ){

        st_value = (st_data)it->second;
        st_value.incr_frame(recv_frame);
        it->second = st_value;
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


    }


}
void printdata::get_st_newmap(bssid* recv_bssid_addr,station* recv_station_addr)
{

    print_st_data::iterator it;
    it = st_data1.find(make_pair((bssid)*recv_bssid_addr,(station)*recv_station_addr));
    if(it == st_data1.end() ){

        //none data append new map
        memcpy(&recv_bssid,recv_bssid_addr,6);
        memcpy(&recv_station,recv_station_addr,6);
        st_data1.insert(print_st_data::value_type(make_pair(recv_bssid,recv_station),st_value));//none data insert


    }else{
        //if has data regen?
        for(it = st_data1.begin(); it!= st_data1.end();++it)
        {
      //      ((bssid)(it->first)).print_mac();
            //test->print_mac();
        }
    }
}
printdata::ap_data& printdata::pass_ap_data()
{

    return ap_value;
}

printdata::st_data& printdata::pass_st_data()
{

    return st_value;
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
    string str2 ="BSSID\t\t           STATION\t     FRAMES   PROBE\n";
    cout <<str2 <<"\n";
    print_st_data::iterator it2;

    for(it2 = st_data1.begin(); it2 != st_data1.end();++it2)
    {
        ((bssid)((it2->first).first)).print_mac();
        ((station)((it2->first).second)).print_mac();
        ((st_data)(it2->second)).print_frame();
        printf("\n");

    }
}

void printdata::data_zero_init()
{
    ap_value = {};
    recv_bssid = {};
    st_value = {};
    recv_station ={};
}

