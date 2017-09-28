#include <iostream>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include "mac80211.h"
#include "radiotap.h"
#include "printdata.h"
#include <vector>
#include <string>
#include <cstring>
using namespace std;

#define PROMISCUOUS true;

//reguler express need
char *correct_dev(int argu_count,char *argu_vector);
void packet_control(pcap_t * packet_descriptor,pcap_stat& stat);
void print_ap_data();
void print_station_data();
void get_ap_datas(printdata::ap_data&ref1,mac80211::ap_data&ref2);
void get_st_datas(printdata::st_data&ref1,mac80211::st_data&ref2);

struct print_all_data{};

int main(int argc, char *argv[])
{
    char *dev =correct_dev(argc,argv[1]);

    char errbuf[PCAP_ERRBUF_SIZE];
    int flags = PROMISCUOUS;

    pcap_t *packet_descriptor = pcap_open_live(dev, BUFSIZ, flags, 300, errbuf);
    struct pcap_stat stat;
    if(packet_descriptor == NULL) {
        printf("%s\n",errbuf);
        exit(1);
    }else{
        packet_control(packet_descriptor,stat);

    }
    return 0;
}
char *correct_dev(int argu_count,char *argu_vector)
{
    if (argu_count != 2){
        printf("use this form to use program\nProgramName DeviceName\n");
        exit(1);
    }
    printf("Device : %s\n", argu_vector);
    return argu_vector;
}

void packet_control(pcap_t * packet_descriptor,pcap_stat& stat)
{

    //typedef std::map<int,std::string> cip_map;
    //typedef std::map<int,std::string>::iterator cip_map_iter;


    int loopstatus = 0;
    const u_char *pkt_data;
    struct pcap_pkthdr *pkt_hdr;
    mac80211 Obj;
    printdata  Prints;


    while((loopstatus = pcap_next_ex(packet_descriptor, &pkt_hdr, &pkt_data)) >= 0){//pkt_data 's adress
       (void)pkt_hdr;//useless
        pcap_stats(packet_descriptor,&stat);


        if(loopstatus == 0)
            continue;//timeout check

        Obj.get_rth_leng((uint8_t*)pkt_data);//rth length get
        Obj.get_common_data((uint8_t *)pkt_data,pkt_hdr->len);

        //confirm data
        bool bssid_check = true;//have data then no run


        bssid_check = Prints.chk_bssid((printdata::bssid*)Obj.pass_ap_bssid());
        //confirm station same in

        if(bssid_check == false){
            Obj.get_mac802_cntdata();
            Prints.get_ap_regen((printdata::bssid*)Obj.pass_ap_bssid(),Obj.pass_ap_regen_beacon(),Obj.pass_ap_regen_data());
        }else {
            Obj.get_mac802_data();//mac802 get data

            get_ap_datas(Prints.pass_ap_data(),Obj.pass_ap_value());//data transfer to Obj ->Print
            Prints.get_ap_newmap((printdata::bssid*)Obj.pass_ap_bssid());
        }


        //***************** station
        bool station_check = false;//have data then run(true)
        station_check = Prints.chk_station((printdata::bssid*)Obj.pass_ap_bssid(),(printdata::station*)Obj.pass_st_station());
        Obj.get_station_cntdata();
        if(station_check == true)
            //if has key in the map and right packet than set st_data regen.
            Prints.get_st_regen((printdata::bssid*)Obj.pass_ap_bssid(),(printdata::station*)Obj.pass_st_station(),Obj.pass_st_frame());
        else{

            //Obj.get_station_data();//mac802 get data
            if (Obj.pass_cmp_bs_st() == true){//bssid == destination
                get_st_datas(Prints.pass_st_data(),Obj.pass_st_value());//data transfer to Obj ->Print
                Prints.get_st_newmap((printdata::bssid*)Obj.pass_ap_bssid(),(printdata::station*)Obj.pass_st_station());

            }
        }


        Prints.print_cmd_ap();
        Prints.data_zero_init();


    }
    if(loopstatus == -1 || loopstatus == -2)
          pcap_perror(packet_descriptor,"Packet data read error");


}

void get_ap_datas(printdata::ap_data&ref1,mac80211::ap_data&ref2)
{
    ref1.get_channel(ref2.channel);
    ref1.get_cipher(ref2.cipher);
    ref1.get_auth(ref2.auth);
    ref1.get_encrypt(ref2.encrpt);
    ref1.get_ssid((uint8_t*)&ref2.ssid[0],ref2.ssid_len());
    ref1.incr_beacon(ref2.pass_beacon());
    ref1.incr_data_pack(ref2.pass_data_pack());
}


void get_st_datas(printdata::st_data&ref1,mac80211::st_data&ref2)
{
    ref1.incr_frame(ref2.pass_frame());
    ref1.get_probe((uint8_t*)&ref2.probe[0],ref2.probe_len());

}
void print_station_data()
{

}
