/*
 * This file is part of PowerDNS or dnsdist.
 * Copyright 2017 PowerDNS.COM B.V. and its contributors
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
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <cmath>
#include "dnsparser.hh"
#include "sstuff.hh"
#include "misc.hh"
#include "dnswriter.hh"
#include "dnsrecords.hh"
#include <thread>
#include <mutex>
#include "statbag.hh"
#include "base32.hh"
#include "dnssecinfra.hh"
#include <fstream>
#include <netinet/tcp.h>
#include "json11.hpp"

StatBag S;

vector<ComboAddress> getResolvers()
{
  vector<ComboAddress> ret;
  ifstream ifs("/etc/resolv.conf");
  if(!ifs)
    return ret;

  string line;
  while(std::getline(ifs, line)) {
    boost::trim_right_if(line, is_any_of(" \r\n\x1a"));
    boost::trim_left(line); // leading spaces, let's be nice

    string::size_type tpos = line.find_first_of(";#");
    if(tpos != string::npos)
      line.resize(tpos);

    if(boost::starts_with(line, "nameserver ") || boost::starts_with(line, "nameserver\t")) {
      vector<string> parts;
      stringtok(parts, line, " \t,"); // be REALLY nice
      for(vector<string>::const_iterator iter = parts.begin()+1; iter != parts.end(); ++iter) {
        try {
          ret.push_back(ComboAddress(*iter, 53));
        }
        catch(...)
        {
        }
      }
    }
  }
  return ret;
}

vector<DNSName> getNS(vector<ComboAddress>& resolvers, const DNSName& tld)
{
  vector<DNSName> ret;
  vector<uint8_t> packet;
  DNSPacketWriter pw(packet, tld, QType::NS);
  pw.getHeader()->rd=1;  
  pw.addOpt(2800, 0, EDNSOpts::DNSSECOK);
  pw.commit();

  for(const auto& r: resolvers) {
    try {
      Socket sock(r.sin4.sin_family, SOCK_DGRAM);
      sock.connect(r);
      sock.send(string((const char*)&packet[0], packet.size()));
      string reply;
      sock.read(reply);
      MOADNSParser mdp(false, reply);
     
      for(const auto& a : mdp.d_answers) {
        if(a.first.d_type == QType::NS && a.first.d_name == tld) {
          ret.push_back(getRR<NSRecordContent>(a.first)->getNS());
        }
      }
      if(!ret.empty())
        break;
    }
    catch(...) {}
  }
  return ret;
}

vector<ComboAddress> lookupAddr(const vector<ComboAddress>& resolvers, const DNSName& server, uint16_t qtype)
{
  vector<ComboAddress> ret;
  vector<uint8_t> packet;
  DNSPacketWriter pw(packet, server, qtype);
  pw.getHeader()->rd=1;
  pw.addOpt(2800, 0, EDNSOpts::DNSSECOK);
  pw.commit();

  for(const auto& r: resolvers) {
    try {
      Socket sock(r.sin4.sin_family, SOCK_DGRAM);
      sock.connect(r);
      sock.send(string((const char*)&packet[0], packet.size()));
      string reply;
      sock.read(reply);
      MOADNSParser mdp(false, reply);
     
      for(const auto& a : mdp.d_answers) {
        if(a.first.d_type == qtype && a.first.d_name == server) {
          ret.push_back(getAddr(a.first, 53));
        }
      }
      if(!ret.empty())
        break;
    }
    catch(...) {}
  }
  return ret;
}

struct
{
  void insert(const pair<uint64_t, uint64_t>& p)
  {
    std::lock_guard<std::mutex> lock(d_mut);
    d_distances.insert(p);
  }

  unsigned int size()
  {
    std::lock_guard<std::mutex> lock(d_mut);
    return d_distances.size();
  }

  uint64_t getEstimate()
  {
    std::lock_guard<std::mutex> lock(d_mut);
    double lin=0;
    double full=pow(2.0,64.0);
    for(const auto& d: d_distances) 
      lin+=full/(d.second-d.first);
    
    return lin/d_distances.size();
  }

  void log(ofstream& of)
  {
    std::lock_guard<std::mutex> lock(d_mut);
    of<<d_distances.size()<<"\t";
    double lin=0;
    double full=pow(2.0,64.0);
    for(const auto& d: d_distances) 
      lin+=full/(d.second-d.first);
    of<<lin/d_distances.size()<<endl;
  }
  
  set<pair<uint64_t, uint64_t>> d_distances;
  std::mutex d_mut;

} Distances;

//ofstream g_log("log");

uint8_t g_characters=12;

uint64_t numberify(const std::string& str)
{
  //  cout<<"Input: '"<<str<<"', size: "<<str.size()<<endl;
  int pos=g_characters;
  uint64_t ret=0;
  for(auto& c : str) {
    uint8_t val;
    if(c>= '0' && c<='9')
      val = c-'0';
    else if(c>='a' && c<='z')
      val = 10+ (c-'a');
    else if(c>='A' && c<='Z')
      val = 10+ (c-'A');
    else val = 37;
    ret*=37;
    ret+=val;
    //    cout<<pos<<": "<<c<<", "<<(int)val<<endl;
    if(!--pos)
      break;
  }
  while(pos) {
    //    cout<<pos<<": pad"<<endl;
    ret*=37;
    --pos;
  }
  return ret;
  
}

std::atomic<unsigned int> g_querycounter;
unsigned int g_limit = 4096;
bool g_nsecZone;
void askAddr(const DNSName& tld, const ComboAddress& ca)
try
{
  Socket sock(ca.sin4.sin_family, SOCK_STREAM);

  int tmp=1;
  if(setsockopt(sock.getHandle(), IPPROTO_TCP, TCP_NODELAY,(char*)&tmp,sizeof tmp)<0) 
    throw runtime_error("Unable to set socket no delay: "+string(strerror(errno)));
  setNonBlocking(sock.getHandle());
  sock.connect(ca, 1);
  setBlocking(sock.getHandle());

  struct timeval timeout;
  timeout.tv_sec = 1;
  timeout.tv_usec = 0;

  if (setsockopt (sock.getHandle(), SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout)) < 0)
    throw PDNSException("Unable to set SO_RCVTIMEO option on socket: " + stringerror());

  if (setsockopt (sock.getHandle(), SOL_SOCKET, SO_SNDTIMEO, (char *)&timeout, sizeof(timeout)) < 0)
    throw PDNSException("Unable to set SO_SNDTIMEO option on socket: " + stringerror());

  
  int count=0;
  
  while(g_querycounter < g_limit) {
    g_querycounter++;
    uint16_t len;
    vector<uint8_t> packet;
    uint64_t rnd = 1ULL*random()*random();
    string query = toBase32Hex(string((char*)&rnd, 8));
    auto pos = query.find('=');
    if(pos != string::npos)
      query.resize(pos);
    DNSName qname(query);
//    cout<<qname<<endl;
    qname+=tld;
    
    DNSPacketWriter pw(packet, qname, QType::A);

    pw.addOpt(2800, 0, EDNSOpts::DNSSECOK);
    pw.commit();

    len = htons(packet.size());
    if(sock.write((char *) &len, 2) != 2)
      throw PDNSException("tcp write failed");

    sock.writen(string((char*)&*packet.begin(), (char*)&*packet.end()));

    if(count++ < 10)
      continue;

    int ret=sock.read((char *) &len, 2);
    if(!ret)
      throw PDNSException("EOF on TCP");
    if(ret!=2)
      throw PDNSException("tcp read failed, read "+std::to_string(ret) + " bytes");
    
    len=ntohs(len);
    scoped_array<char> creply(new char[len]);
    readn2(sock.getHandle(), creply.get(), len);
    
    string reply(creply.get(), len);
    
    MOADNSParser mdp(false, reply);
    bool seenDNSSEC=false;
    if(mdp.d_header.rcode != RCode::NXDomain) {
      continue;
    }
    for(MOADNSParser::answers_t::const_iterator i=mdp.d_answers.begin(); i!=mdp.d_answers.end(); ++i) {
      if(i->first.d_type == QType::NSEC) {
        g_nsecZone=true;
        seenDNSSEC=true;
        NSECRecordContent r = dynamic_cast<NSECRecordContent&> (*(i->first.d_content));
        uint64_t from=0, to=0;
        auto firstlabel=i->first.d_name.getRawLabels()[0];
        from = numberify(firstlabel);
        firstlabel=r.d_next.getRawLabels()[0];
        to = numberify(firstlabel);
        if(from < to){
          //          cout<<"Ratio: "<<(pow(37.0,(double)g_characters)/(1.0*to-from))<<", "<<to-from<<", "<<to<<" "<<from<<endl;
          Distances.insert({from,to});
        }
      }
      else if(i->first.d_type == QType::NSEC3) {
        seenDNSSEC=true;
        NSEC3RecordContent r = dynamic_cast<NSEC3RecordContent&> (*(i->first.d_content));
        auto nsec3from=fromBase32Hex(i->first.d_name.getRawLabels()[0]);
        uint64_t from, to;
        memcpy(&from, nsec3from.c_str(), 8);
        memcpy(&to, r.d_nexthash.c_str(), 8);
        from=be64toh(from);
        to=be64toh(to);
        //        cout<<"Ratio: "<<0xffffffffffffffffULL/(1.0*to-from)<<", "<<to-from<<", ffs: "<<__builtin_clzll(to-from)<<endl;
        
        Distances.insert({from,to});
        //        Distances.log(g_log);
      }
      else if(i->first.d_type == QType::RRSIG || i->first.d_type == QType::DS) {
        seenDNSSEC=true;
      }
    }
    if(!seenDNSSEC) {
      throw std::runtime_error("Did not see DNSSEC in response");
    }
  }
}
catch(std::exception& e) {
  cerr<<"Ask addr thread for "<<ca.toString()<<" died on: "<<e.what()<<endl;
}
catch(PDNSException& pe) {
  cerr<<"Ask addr thread for "<<ca.toString()<<" died on: "<<pe.reason<<endl;
}

void askName(const DNSName& tld, const vector<ComboAddress>& resolvers, const DNSName& name, uint16_t qtype)
{
  auto addr = lookupAddr(resolvers, name, qtype);
  vector<std::thread> threads;
  for(const auto& a : addr) {
    cout<<a.toString()+" "; cout.flush();
    threads.emplace_back(std::thread(askAddr, tld, a));
  }
  for(auto&t : threads)
    t.join();
}



// dnssecmeasure domain IP
int main(int argc, char** argv)
try
{
  reportAllTypes();
  signal(SIGPIPE, SIG_IGN);
  auto resolvers=getResolvers();
  DNSName tld(argv[1]);
  auto tldservers = getNS(resolvers, tld);
  vector<std::thread> threads;

  if(argc > 2)
    g_limit=atoi(argv[2]);
    
  cout<<"Will send "<<g_limit<<" queries to: ";
  for(const auto& name: tldservers) {
    cout<<name<<" ";
  }
  cout<<endl; 
  for(const auto& name: tldservers) {
    threads.push_back(std::thread(askName, tld, resolvers, name, QType::A));
    threads.push_back(std::thread(askName, tld, resolvers, name, QType::AAAA));
  }
  for(auto& t : threads) {
    t.join();
  }

  using namespace json11;
  
  ofstream distfile("distances");
  double lin=0;
  double range = g_nsecZone ? pow(37.0, g_characters) : pow(2.0, 64.0);
  double estimate=0;
  if(!Distances.d_distances.empty()) {
    for(const auto& d: Distances.d_distances) {
      distfile<<(d.second-d.first)<<"\t"<<((d.second-d.first)>>39) << "\t" << (uint64_t)(range/(d.second-d.first)) <<endl;
      lin+= range/(d.second-d.first);
    }
    estimate = lin / Distances.d_distances.size();
  }
  cout<<"\n"<<argv[1]<<" poisson size "<<estimate<<endl;
  cout<<"Based on "<<g_querycounter<<" queries"<<endl;

  auto obj=Json::object {
    { "zone", argv[1]},
    { "dnssec", Distances.d_distances.empty() ? false : true},
    { "nsec-type", g_nsecZone ? "NSEC" : "NSEC3" },
    { "delegation-estimate", (double)(uint64_t)estimate},
    { "queries", (double)g_querycounter}
  };
  
  Json output = obj;
  cout<< output.dump() <<endl;
  
  exit(EXIT_SUCCESS);
}
catch(std::exception &e)
{
  cerr<<"Fatal: "<<e.what()<<endl;
}
catch(PDNSException &e)
{
  cerr<<"Fatal: "<<e.reason<<endl;
}
