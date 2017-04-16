#include "generate_packet.h"
#include "libnet-headers.h"
generate_packet::generate_packet()
{

}
packet_info ::packet_info(char *_consol_dev,char *_consol_sender_ip,char *_consol_target_ip)
{
    dev_name=_consol_dev;
/*
struct libnet_ethernet_hdr
{
    u_int8_t  ether_dhost[ETHER_ADDR_LEN]; destination ethernet address
    u_int8_t  ether_shost[ETHER_ADDR_LEN];source ethernet address
    u_int16_t ether_type;                  protocol
    u_int16_t ar_pro;
    u_int8_t  ar_hln;
    u_int8_t  ar_pln;
    u_int16_t ar_op;
}*/
