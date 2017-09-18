#include "printdata.h"
using namespace std;
printdata::printdata()
{
    ap_data1 = new print_ap_data;
    recv_bssid = new bssid;
    ap_value = new ap_data{0,0,0,"","","",""};


}
printdata::~printdata()
{
    delete[] recv_bssid;
    delete[] ap_data1;
    delete[] ap_value;

}
//void printdata::pass_data(bssid& mac_info,ap_data& pack_info)
//{
    //recv_bssid = mac_info
    //ap_value = pack_info
//}

void printdata::get_ap_bssid(uint8_t* recv_bssid_addr)
{

    printf("\nbefore check1: %02x \n",recv_bssid_addr[1]);//check_recv_struct
    bssid& test = (bssid&)*recv_bssid_addr;

    print_ap_data::iterator it;
    it = ap_data1->find(test);
    if(it == ap_data1->end() ){
        printf("none data at map \n");
        //insert_new_map();
        memcpy(&recv_bssid->mac_arr[0],recv_bssid_addr,6);

        ap_data1->insert(print_ap_data::value_type(*recv_bssid,*ap_value));//none data insert
        for(it = ap_data1->begin(); it!= ap_data1->end();++it)
        {
            //bssid* test = );
            ((bssid*)&(it->first))->print_mac();
            printf("\n\n");
        }
    }else{

        printf("\nfound\n\n");
        for(it = ap_data1->begin(); it!= ap_data1->end();++it)
        {
            bssid* test = (bssid*)&(it->first);
            test->print_mac();
        }
    }
}



