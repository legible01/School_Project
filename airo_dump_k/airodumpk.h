#ifndef AIRODUMPK_H
#define AIRODUMPK_H
#include <cstdio>
#include <cstdlib>
#include <string>
#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <vector>


class AiroDumpK
{
public:
    struct RadioTapHeader{
       uint8_t rth_revision;
       uint8_t rth_pad;
       uint16_t rth_leng;
    }__attribute__((packed));//same as pragma(1)
    struct Mac802Header{
        uint16_t m802_fc;//framecontrol
        uint16_t m802_dur;
        uint8_t m802_addr1[6];
        uint8_t m802_addr2[6];
        uint8_t m802_addr3[6];
        uint16_t m802_seq;
    }__attribute__((packed)) M802H;
    int


    AiroDumpK();
    int find_802macframe(u_char *pack_front);
        /*void allocate_param(int p_count,char *param_dev);
        void set_param_ip(char **param_ip);//param input
        void set_param_mac(pcap_t * pack_d);
        void delete_param_mem();//var delete*/
};

#endif // AIRODUMPK_H
