#include <iostream>
#include "libnet-headers.h"
#include "packet_info.h"
#include <cstdio>
#include <pcap.h>
#include "packet_info.h"
#include "generate_packet.h"
#include <stdint.h>
#include <cstring>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <cstring>
#include <arpa/inet.h>
#include <net/if.h>
#include <vector>

using namespace std;

int main(int argc, char *argv[])
{

    printf("hello1");
    packet_info pack_info;

    pack_info.allocate_param(argc,argv[1]);
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t * pd = pcap_open_live(pack_info.get_my_dev(),BUFSIZ,1,1,errbuf);//1sec

    printf("\nhello2");
    pack_info.set_my_info();
    printf("\nhello3\n");
    printf("ip: %s %s\n",argv[2],argv[3]);
    printf("ip_address %x  %x\n",&argv[2],&argv[3]);
    pack_info.set_param_ip(&argv[2]);
    pack_info.set_param_mac(pd);
    generate_packet recovery_packet(pack_info.get_param_count());



    //pack_info.delete_param_mem();

    //pack_info.set_param(argc,argv[]);



    //generate_packet proto_pack();
    //packet_info pack_info;
    //struct libnet_802_3_hdr eth;
    //cout << "Hello World!" << endl;

    //printf(" %d ",pack_info.arp_iph_size());
    //make chogihwa
    //make
    return 0;
}
//make map and memory cmp and that key is ip?
