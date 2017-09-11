#include <iostream>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include "mac80211.h"
#include "radiotap.h"
#include <vector>
#include <string>
#include <cstring>
using namespace std;

#define PROMISCUOUS true;

//reguler express need
char *correct_dev(int argu_count,char *argu_vector);
void packet_control(pcap_t * packet_descriptor);
void print_ap_data();
void print_station_data();

struct print_all_data{};

int main(int argc, char *argv[])
{
    char *dev =correct_dev(argc,argv[1]);

    char errbuf[PCAP_ERRBUF_SIZE];
    int flags = PROMISCUOUS;

    pcap_t *packet_descriptor = pcap_open_live(dev, BUFSIZ, flags, 300, errbuf);
    if(packet_descriptor == NULL) {
        printf("%s\n",errbuf);
        exit(1);
    }else{
        packet_control(packet_descriptor);

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

void packet_control(pcap_t * packet_descriptor)
{

    //typedef std::map<int,std::string> cip_map;
    //typedef std::map<int,std::string>::iterator cip_map_iter;


    int loopstatus = 0;
    const u_char *pkt_data;
    struct pcap_pkthdr *pkt_hdr;
    mac80211 Obj;
    std::vector<unsigned char>type_802m_packs(9);
    type_802m_packs[0] = 0x80;//beaconframe
    type_802m_packs[1] = 0x08;//data
    type_802m_packs[2] = 0xD4;//acknowledgement
    type_802m_packs[3] = 0x94;//Block Ack
    type_802m_packs[4] = 0xc4;//clear to send
    type_802m_packs[5] = 0x48; //nullfuntion
    type_802m_packs[6] = 0x84;//Block Ack Req
    type_802m_packs[7] = 0x88;//QOS Data
    type_802m_packs[8] = 0xb4;//Request-to-send





    while((loopstatus = pcap_next_ex(packet_descriptor, &pkt_hdr, &pkt_data)) >= 0){//pkt_data 's adress
       (void)pkt_hdr;//useless


        if(loopstatus == 0)
            continue;//timeout check

        //struct RadioTapHeader * packet_p=(struct RadioTapHeader *)pkt_data;//pkt_data->data(adress)
//struct libnet_ethernet_hdr * recv_packet=(struct libnet_ethernet_hdr *)packet_data;
        //system("clear");
        string str1 ="BSSID\t\t   PWR  Beacons     #Data,   ESSID\n";
        //print_ap_data;
        //print_station_data;
        Obj.get_rth_leng((uint8_t*)pkt_data);
        Obj.get_802mac_type((u_char *)pkt_data);
        Obj.get_802mac_data();
        //uint8_t * m802h_addr = (uint8_t *)pkt_data+rth_len;



        //printf("%02x\n",*m802h_addr);
        //cout<< str1 << endl;



            //printf("main: %d\n",rth_len);

        //printf("hello\n");
        //if(iph_print(&packet_p,&tcpd_len) == -1)
          //  continue;//return value 0 then mov next function and if value -1 then restart loop
       // if(tcph_print(&packet_p,&tcpd_len) == -1)
        //    continue;
       // findhostadr(&packet_p,tcpd_len);
        //tcpd_print(&packet_p,tcpd_len);

    }
    if(loopstatus == -1 || loopstatus == -2)
          pcap_perror(packet_descriptor,"Packet data read error");


}


void print_ap_data()
{

}
void print_station_data()
{

}
