#define __FAVOR_BSD
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "statbag.hh"
#include "dnspcap.hh"
#include "dnsparser.hh"
#include <boost/tuple/tuple.hpp>
#include <boost/tuple/tuple_comparison.hpp>
#include <map>
#include <set>
#include <fstream>
#include <algorithm>
#include "anadns.hh"

#include "namespaces.hh"

StatBag S;

struct Entry
{
  ComboAddress ip;
  uint16_t port;
  uint16_t id;

  bool operator<(const struct Entry& rhs) const 
  {
    return tie(ip, port, id) < tie(rhs.ip, rhs.port, rhs.id);
  }
};


typedef map<Entry, uint32_t> emap_t;
emap_t ecount;

int main(int argc, char** argv)
try
{
  for(int n=1 ; n < argc; ++n) {
    cout<<argv[n]<<endl;
    PcapPacketReader pr(argv[n]);
    
    Entry entry;
    ComboAddress addr("181.121.82.249:0"), theirs1, theirs2;;
    while(pr.getUDPPacket()) {
      if((ntohs(pr.d_udp->uh_dport)==53 || ntohs(pr.d_udp->uh_dport)==53) &&   pr.d_len > 12) {
        try {
          dnsheader* dh= (dnsheader*) pr.d_payload;

          theirs1=pr.getSource();
          theirs2=pr.getDest();
          theirs1.sin4.sin_port = theirs2.sin4.sin_port = 0;
          if(theirs1 != addr && theirs2 != addr)
            continue;

          MOADNSParser mdp((const char*)pr.d_payload, pr.d_len);

          cout <<mdp.d_qname<<"', "<<mdp.d_qtype<<", " << pr.d_pheader.ts.tv_sec <<", " << pr.d_pheader.ts.tv_usec<<" "<<pr.d_len<<endl;

        }
        catch(MOADNSException& mde) {
          //        cerr<<"error parsing packet: "<<mde.what()<<endl;
          continue;
        }
        catch(std::exception& e) {
          cerr << e.what() << endl;
          continue;
        }
      }
    }
  }
  cout <<"commit;";
  /*
  for(emap_t::const_iterator i = ecount.begin(); i != ecount.end(); ++i) {
    if(i->second > 1)
      cout << U32ToIP(ntohl(i->first.ip)) <<":"<<ntohs(i->first.port)<<" -> "<<i->second <<endl;
  }
  */

}
catch(std::exception& e)
{
  cerr<<"Fatal: "<<e.what()<<endl;
}
