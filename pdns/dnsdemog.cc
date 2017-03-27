/*
 * This file is part of PowerDNS or dnsdist.
 * Copyright -- PowerDNS.COM B.V. and its contributors
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of version 2 of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * In addition, for the avoidance of any doubt, permission is granted to
 * link this program with OpenSSL and to (re)distribute the binaries
 * produced as the result of such linking.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
#define __FAVOR_BSD
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "statbag.hh"
#include "dnspcap.hh"
#include "dnsparser.hh"
#include <unordered_set>
#include <unordered_map>
#include <map>
#include <set>
#include <fstream>
#include <algorithm>
#include "anadns.hh"

#include "namespaces.hh"

StatBag S;

time_t granu(time_t in, int mod)
{
  return in - (in % mod);
}

int main(int argc, char** argv)
try
{
  std::unordered_map<DNSName, uint32_t> dcounts;
  struct Bin
  {
    Bin(int i) : interval(i), ofs(string("plot.")+std::to_string(i))
    {
    };
    int interval;
    std::unordered_map<DNSName, uint32_t> dset;
    std::unordered_map<ComboAddress, uint32_t, ComboAddress::addressOnlyHash> cset;
    uint64_t queries=0;
    time_t lastsec=0;
    ofstream ofs;
  };  
  
  vector<Bin> bins; 
  for(auto i : {30})
    bins.emplace_back(i);

  SuffixMatchTree<bool> smt;
  //  for(const auto& s : {"metric.gstatic.com", "tengyin520.com", "mcafee.com", "spamhaus.org", "sophosxl.net", "ampproject.net", "1yf.de", "e5.sk"})
  //    smt.add(DNSName(s), true);


  time_t begin=0;
  uint64_t totqueries=0;
  ofstream tots("tots");
  for(int n=1 ; n < argc; ++n) {
    PcapPacketReader pr(argv[n]);
    
    while(pr.getUDPPacket()) {
      if(ntohs(pr.d_udp->uh_dport)==53 &&  pr.d_len > 12) {
        try {
          dnsheader* dh= (dnsheader*) pr.d_payload;

          if(!dh->rd || dh->qr)
            continue;

          uint16_t qtype=0;
          DNSName dn((const char*)pr.d_payload, pr.d_len, 12, false, &qtype);
          if(dn.countLabels()==1 || smt.lookup(dn))
            continue;
          auto src = pr.getSource();
          src.sin4.sin_port = 0;

          dcounts[dn]++;
          if(!begin)
            begin = pr.d_pheader.ts.tv_sec;
          totqueries++;
          for(auto& b : bins) {
              
            b.cset[src]++;
            b.dset[dn]++;
            b.queries++;
            if(!b.lastsec) {
              b.lastsec = granu(pr.d_pheader.ts.tv_sec, b.interval);
              continue;
            }
            if(granu(pr.d_pheader.ts.tv_sec, b.interval) != b.lastsec) {
              if(b.interval==bins.begin()->interval) {
                tots<<pr.d_pheader.ts.tv_sec-begin<<"\t"<<totqueries<<"\t"<<dcounts.size();
                for(int n=1; n<10;++n) {
                  tots<<"\t"<< std::count_if(dcounts.begin(), dcounts.end(), [n,&b](const auto& p) {
                      return p.second > n*b.queries/10000.0;
                    });
                }
                tots<<"\n";
                tots.flush();
              }


              
              b.ofs<<b.lastsec<<"\t"<<b.cset.size()<<"\t"<<b.dset.size()<<"\t"<<b.queries<<"\t";
              b.ofs<<std::count_if(b.cset.begin(), b.cset.end(), [](const auto& p) {
                  return p.second > 2;
                });
              b.ofs<<"\t";
              b.ofs<<std::count_if(b.dset.begin(), b.dset.end(), [](const auto& p) {
                  return p.second > 2;
                });
              b.ofs<<endl;
              
              b.ofs.flush();
              b.cset.clear();
              b.dset.clear();
              b.queries=0;
              b.lastsec = granu(pr.d_pheader.ts.tv_sec, b.interval);
            }

          }
        }
        catch(std::exception& e) {
          //          cerr << e.what() << endl;
          continue;
        }
      }
    }
  }

  vector<pair<DNSName, uint32_t> > rcount;
  for(const auto& cp : dcounts)
    rcount.push_back(cp);

  sort(rcount.begin(), rcount.end(), [](const auto& a, const auto& b) {
      return a.second < b.second;
    });

  ofstream popi("popi");
  uint64_t cumul=0;
  for(const auto rc : rcount) {
    popi<<rc.second<<"\t"<<cumul<<"\t"<<rc.first.labelReverse()<<"\n";
    cumul+=rc.second;
  }

  auto busiest=rcount.rbegin()->second;
  cout<<"Busiest domain had "<<busiest<<" visits\n";
  vector<uint32_t> hbins(4096);
  for(const auto& rc : rcount) {
    hbins[rc.second*(hbins.size()-1)/busiest]++;
  }
  ofstream histo("histo");
  int place=0;
  for(const auto& hb : hbins) {
    histo<<busiest*place/(hbins.size()-1.0)<<"\t"<<hb<<"\n";
    place++;
  }
}
catch(std::exception& e)
{
  cerr<<"Fatal: "<<e.what()<<endl;
}
