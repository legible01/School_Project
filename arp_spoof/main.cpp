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

#define NONE_PACK       1
#define ARP_DIRECT_REQ  2
#define ARP_REQ         3
#define IP_PACKET       4

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
    recovery_packet.arp_reply_set(pack_info);
    printf("1111\n\n");
    recovery_packet.send_arp_reply(pd,2);
    int loopstatus = 0;
    const uint8_t *pkt_data;
    struct pcap_pkthdr *pkt_hdr;
    return 0;
}

void packet_filter(pcap_t *pack_d)
{
    std ::vector<uint16_t>packet_type;



    printf("\n\nhere1?");
    int pack_type_chk;
    while((loopstatus = pcap_next_ex(pack_d, &pkt_hdr, &pkt_data)) >= 0){//pkt_data 's adress
        (void)pkt_hdr;//useless
        printf("\n\nhere1\n %d \n",loopstatus);
        if(loopstatus == 0)
            continue;



        pack_type_chk = memcmp


        switch(){
            if(arp_req_check((struct libnet_ethernet_hdr *)pkt_data)== -1)
                continue;
        case():
            if(ip_pack_check((uint8_t *)pkt_data,flag,count) == -1)//packet_data,ip,info_struc
                continue;//return value 0 then mov next function and if value -1 then restart loop
        }

        printf("end1;");
        printf("\nhere2?");
        printf("\nGet MacAddress Done.\n");

        break;

    }
    if(loopstatus == -1 || loopstatus == -2)
        pcap_perror(pack_d,"Packet data read error");



}
int arp_req_check()


    //pack_info.delete_param_mem();

    //pack_info.set_param(argc,argv[]);



    //generate_packet proto_pack();
    //packet_info pack_info;
    //struct libnet_802_3_hdr eth;
    //cout << "Hello World!" << endl;

    //printf(" %d ",pack_info.arp_iph_size());
    //make chogihwa
    //make

//make map and memory cmp and that key is ip?
