#include "printdata.h"
using namespace std;
printdata::printdata()
{
    ap_data1 = new print_ap_data;
    recv_bssid = new bssid;
    ap_value = new ap_data{0,0,0,0,"","",""};
}
printdata::~printdata()
{
    delete[] recv_bssid;
    delete[] ap_data1;
    delete[] ap_value;

}

void printdata::get_ap_bssid(uint8_t* recv_bssid_addr)
{
    memcpy(&recv_bssid->mac_arr[0],recv_bssid_addr,6);
    printf("\nbefore check1: %02x \n",recv_bssid_addr[1]);
    printf("\nbefore check2: %02x \n",recv_bssid->mac_arr[1]);
    if((ap_data1->count(*recv_bssid)) == 0){
    //ap_data1->insert(map<bssid,ap_data>::value_type(recv_bssid,ap_value));
   // ap_data1[&recv_bssid]=ap_value;
    ap_data1->insert(std::make_pair(recv_bssid,*ap_value));
        //not matched
    }else{

        printf("\nfound\n");
        //if has same address
       // printf("\ncount? : %d\n",a);
        //not need input bssid ,input other datas

   }

    //recv_bssid = recv_bssid_addr;
    //recv_bssid = tie(*recv_bssid_addr[0],*recv_bssid_addr[1],*recv_bssid_addr[2],*recv_bssid_addr[3],*recv_bssid_addr[4],*recv_bssid_addr[5])
    /*for( ){
        recv_bssid[0] = r1

    }*/

   // std::cout<<" " << std::get<0>(recv_bssid);
    //uint8_t r=(uint8_t*)recv_bssid[1];


    //for(const auto i: *recv_bssid)
   //for(re)
   // {

   //     std::cout <<it_a<< ' ';

   // }



    /*for(map<bssid,ap_data>::iterator it = ap_data1.begin(); it!=ap_data1.end();++it)
    {if(it )
    }

*/

    /*auto ap_bss_chk = ap_data1.find();//value)

    if(ap_bss_chk != ap_data1.end()){
            data_layer = ap_bss_chk->first;
    }else{

    }
*/
}

