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
#include "dnsname.hh"
#include <boost/tuple/tuple.hpp>
#include <boost/tuple/tuple_comparison.hpp>
#include <unordered_map>
#include <map>
#include <set>
#include <fstream>
#include <algorithm>
#include "anadns.hh"
#include <boost/program_options.hpp>

#include <boost/logic/tribool.hpp>
#include "arguments.hh"
#include "namespaces.hh"
#include <deque>
#include "dnsrecords.hh"
#include "statnode.hh"

namespace po = boost::program_options;
po::variables_map g_vm;

ArgvMap& arg()
{	
  static ArgvMap theArg;
  return theArg;
}
StatBag S;



int main(int argc, char** argv)
try
{
  po::options_description desc("Allowed options"), hidden, alloptions;
  desc.add_options()
    ("help,h", "produce help message")
    ("version", "print version number")
    ("rd", po::value<bool>(), "If set to true, only process RD packets, to false only non-RD, unset: both")
    ("ipv4", po::value<bool>()->default_value(true), "Process IPv4 packets")
    ("ipv6", po::value<bool>()->default_value(true), "Process IPv6 packets")
    ("servfail-tree", "Figure out subtrees that generate servfails")
    ("load-stats,l", po::value<string>()->default_value(""), "if set, emit per-second load statistics (questions, answers, outstanding)")
    ("write-failures,w", po::value<string>()->default_value(""), "if set, write weird packets to this PCAP file")
    ("verbose,v", "be verbose");
    
  hidden.add_options()
    ("files", po::value<vector<string> >(), "files");

  alloptions.add(desc).add(hidden); 

  po::positional_options_description p;
  p.add("files", -1);

  po::store(po::command_line_parser(argc, argv).options(alloptions).positional(p).run(), g_vm);
  po::notify(g_vm);
 
  vector<string> files;
  if(g_vm.count("files")) 
    files = g_vm["files"].as<vector<string> >(); 

  if(g_vm.count("version")) {
    cerr<<"dnsscope "<<VERSION<<endl;
    exit(0);
  }

  if(files.empty() || g_vm.count("help")) {
    cerr<<"Syntax: dnstop filename.pcap"<<endl;
    cout << desc << endl;
    exit(0);
  }

  StatNode root;

  bool haveRDFilter=0, rdFilter=0;
  if(g_vm.count("rd")) {
    rdFilter = g_vm["rd"].as<bool>();
    haveRDFilter=1;
    cout<<"Filtering on recursion desired="<<rdFilter<<endl;
  }
  else
    cout<<"Warning, looking at both RD and non-RD traffic!"<<endl;

  bool doIPv4 = g_vm["ipv4"].as<bool>();
  bool doIPv6 = g_vm["ipv6"].as<bool>();

  std::unordered_map<DNSName, uint32_t> counts;
  
  for(unsigned int fno=0; fno < files.size(); ++fno) {
    PcapPacketReader pr(files[fno]);
 
    while(pr.getUDPPacket()) {

      if((ntohs(pr.d_udp->uh_dport)==5300 || ntohs(pr.d_udp->uh_sport)==5300 ||
	  ntohs(pr.d_udp->uh_dport)==53   || ntohs(pr.d_udp->uh_sport)==53) &&
	 pr.d_len > 12) {
	try {
	  if((pr.d_ip->ip_v == 4 && !doIPv4) || (pr.d_ip->ip_v == 6 && !doIPv6))
	    continue;
	  if(pr.d_ip->ip_v == 4) {
	    uint16_t frag = ntohs(pr.d_ip->ip_off);
	    if((frag & IP_MF) || (frag & IP_OFFMASK)) { // more fragments or IS a fragment
	      continue;
	    }
	  }

          struct dnsheader* dh =(struct dnsheader*)pr.d_payload;
          
	  if(haveRDFilter && dh->rd != rdFilter) {
	    continue;
	  }

	  if(dh->qr)
            continue;
	  

	  DNSName dn((const char*)pr.d_payload, pr.d_len, 12, false);
          counts[dn]++;
	}
	catch(MOADNSException& mde) {
	  continue;
	}
	catch(std::exception& e) {

	  continue;
	}
      }
    }
    cout<<"PCAP contained "<<pr.d_correctpackets<<" correct packets, "<<pr.d_runts<<" runts, "<< pr.d_oversized<<" oversize, "<<pr.d_nonetheripudp<<" non-UDP.\n";

  }
  vector<pair<DNSName,uint32_t> > output;
  for(const auto& c : counts)
    output.push_back(c);

  sort(output.begin(), output.end(), [](const pair<DNSName,uint32_t>& a, const pair<DNSName,uint32_t>& b) {
       return a.second < b.second;
    });

  for(const auto& o : output) {
    cout<<o.second<<"\t"<<o.first<<"\n";
  }


}
catch(std::exception& e)
{
  cerr<<"Fatal: "<<e.what()<<endl;
}
