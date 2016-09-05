#define __FAVOR_BSD
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "statbag.hh"
#include "dnspcap.hh"
#include "dnsparser.hh"

#include <map>
#include <unordered_map>
#include <set>
#include <fstream>
#include <algorithm>
#include "anadns.hh"
#include <signal.h>
#include "namespaces.hh"

StatBag S;


struct FlowStat
{
  uint64_t queries{0};
  uint64_t responses{0};
  uint64_t qvolume{0};
  uint64_t rvolume{0};
};


bool g_pleaseQuit;
void pleaseQuitHandler(int)
{
  g_pleaseQuit=true;
}

int main(int argc, char** argv)
try
{
  signal(SIGINT, pleaseQuitHandler);
  std::map<pair<ComboAddress, ComboAddress>, FlowStat> flowstats;

  uint64_t count=0;
  for(int n=1 ; n < argc; ++n) {
    cerr<<"File "<<n<<" out of "<<argc-1<<endl;
    PcapPacketReader pr(argv[n]);
    
    while(pr.getUDPPacket()) {
      if(g_pleaseQuit)
        break;
      if((ntohs(pr.d_udp->uh_dport)==53 || ntohs(pr.d_udp->uh_sport)==53) &&  pr.d_len > 12) {
        try {
          dnsheader* dh= (dnsheader*) pr.d_payload;
          if(dh->rd == 0)
            continue;
          MOADNSParser mdp((const char*)pr.d_payload, pr.d_len);

          ComboAddress originator, responder; 
          if(dh->qr) {
            responder=pr.getSource();
            originator=pr.getDest();
          } else {
            responder=pr.getDest();
            originator=pr.getSource();
          }
          originator.sin4.sin_port = responder.sin4.sin_port = 0;
          auto& val=flowstats[{originator,responder}];
          if(dh->qr) {
            val.responses++;
            val.rvolume += pr.d_len;
          }
          else {
            val.queries++;
            val.qvolume += pr.d_len;
          }

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
      if(!((++count)%100000)) {
        cerr<<"\r"<<count<<" packets, "<<flowstats.size()<<" different flows, "<<pr.getPercentage()<<"% done";
        cerr.flush();
      }
    }
    cerr <<"\n";    
  }
  
  vector<pair<FlowStat, pair<ComboAddress,ComboAddress> > > sums;
  for(const auto& p : flowstats)
    sums.push_back({p.second, p.first});

  /*
  nth_element(sums.begin(), sums.begin()+100, sums.end(), [](const decltype(sums)::value_type& a, const decltype(sums)::value_type& b) { 
      return b.first < a.first;
    });
  */
  sort(sums.begin(), sums.end(), [](const decltype(sums)::value_type& a, const decltype(sums)::value_type& b) { 
      return (b.first.qvolume + b.first.rvolume)/(b.first.queries+b.first.responses) < 
             (a.first.qvolume + a.first.rvolume)/(a.first.queries+a.first.responses);
    });


  for(auto iter = sums.begin(); iter < sums.end(); ++iter) {
    if(iter->first.queries < 100)
      continue;
    cout<<iter->first.queries + iter->first.responses<<"\t"<<iter->second.first.toString()<<" -> "<<iter->second.second.toString();
    if(iter->first.queries) 
      cout<<", avg q: "<<iter->first.qvolume/iter->first.queries;
    if(iter->first.responses)
      cout<<", avg r: "<<iter->first.rvolume/iter->first.responses;
    cout<<endl;
  }

}
catch(std::exception& e)
{
  cerr<<"Fatal: "<<e.what()<<endl;
}
