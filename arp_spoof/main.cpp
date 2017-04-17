#include <iostream>
#include "libnet-headers.h"
#include "packet_info.h"
#include <cstdio>
#include <pcap.h>
using namespace std;

int main(int argc, char *argv[])
{

    printf("%p \n",argv[2]);
    packet_info pack_info;

    pack_info.allocate_param_mem(argc,argv[1]);
    pack_info.set_my_info();
    pack_info.set_param_ip(&argv[2]);
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t * pd = pcap_open_live(pack_info.get_my_dev(),BUFSIZ,1,1,errbuf);//1sec


    pack_info.delete_param_mem();

    //pack_info.set_param(argc,argv[]);



    //generate_packet proto_pack();
    //packet_info pack_info;
    //struct libnet_802_3_hdr eth;
    //cout << "Hello World!" << endl;
    printf("%d",argc);
    //printf(" %d ",pack_info.arp_iph_size());
    //make chogihwa
    //make
    return 0;
}
//make map and memory cmp and that key is ip?
