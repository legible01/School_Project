#ifndef RADIOTAP_H
#define RADIOTAP_H
#include <iostream>
#include <cstdio>
#include <cstdlib>
#include <cstdint>

using namespace std;



class radiotap
{
private:


public:
    typedef struct __attribute__((packed))
    {
       uint8_t rth_revision;
       uint8_t rth_pad;
       uint16_t rth_leng;
    } rt_common_hdr;//same as pragma(1)

    friend class mac80211;
    radiotap();
     void get_rth_info(uint8_t *pack_front);
};

#endif // RADIOTAP_H
