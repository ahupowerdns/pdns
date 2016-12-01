#include "dnsfixer.hh"
#include <sys/socket.h>
#include <netinet/in.h>
#include "misc.hh"
#include "iputils.hh"
#include <sys/ioctl.h>
#include <net/if.h>
#include "dnsparser.hh"
#include "statbag.hh"
#define __FAVOR_BSD
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <linux/if_packet.h>
#include <fstream>
#include <net/ethernet.h> /* the L2 protocols */
#include "dnsrecords.hh"
#include "dolog.hh"
#include <boost/program_options.hpp>

StatBag S;
namespace po = boost::program_options;
po::variables_map g_vm;

int getindex(int s, const std::string& interface)
{
  struct ifreq ifr;
  memcpy(ifr.ifr_name,interface.c_str(), interface.size());
  ifr.ifr_name[interface.size()]=0;
  
  if (ioctl(s,SIOCGIFINDEX,&ifr)==-1) {
    unixDie("getting interface index");
  }
  return ifr.ifr_ifindex;
}

RawUDPListener::RawUDPListener(int port, const std::string& interface)
{
  d_socket = socket(AF_PACKET, SOCK_DGRAM,htons(ETH_P_ALL) );
  if(d_socket < 0)
    unixDie("opening packet socket");
  if(!interface.empty()) {
    
    struct sockaddr_ll iface;
    memset(&iface, 0, sizeof(iface));
    iface.sll_family = AF_PACKET;
    iface.sll_protocol = htons(ETH_P_IP);
    iface.sll_ifindex = getindex(d_socket, interface);
    if(bind(d_socket, (struct sockaddr*)&iface, sizeof(iface)) < 0)
      unixDie("binding to interface");
    
    //    if(setsockopt(d_socket, SOL_SOCKET, SO_BINDTODEVICE, interface.c_str(), interface.size()) < 0)
    //  unixDie("Could not bind to interface");
  }
}

bool RawUDPListener::getPacket(std::string* packet, struct sockaddr_ll* addr)
{
  char buffer[1500];
  *addr={0};

  socklen_t remlen = sizeof(*addr);
  int res=recvfrom(d_socket, buffer, sizeof(buffer), 0, (struct sockaddr*)addr, &remlen);
  if(res < 0)
    return false;
  packet->assign(buffer, res);
  return true;
}

bool RawUDPListener::getPacket(ComboAddress* src, ComboAddress* dst, struct sockaddr_ll* addr, std::string* payload, std::string* whole)
{
  string packet;
  if(!getPacket(&packet, addr))
    return false;
  
  const struct ip *iphdr = (const struct ip*)packet.c_str();
  const struct udphdr *udphdr= (const struct udphdr*)(packet.c_str() + 4 * iphdr->ip_hl);

  src->sin4.sin_family = AF_INET;
  src->sin4.sin_addr = iphdr->ip_src;
  src->sin4.sin_port = udphdr->uh_sport;

  dst->sin4.sin_family = AF_INET;
  dst->sin4.sin_addr = iphdr->ip_dst;
  dst->sin4.sin_port = udphdr->uh_dport;

  auto startpos = 4*iphdr->ip_hl + sizeof(struct udphdr);
  payload->assign(packet.c_str() + startpos, packet.size()-startpos);

  if(whole)
    *whole = packet;
  return true;
}

void RawUDPListener::sendPacket(const std::string& ippacket, const std::string& interface, const std::string& mac)
{
  struct sockaddr_ll addr={0};
  addr.sll_family=AF_PACKET;
  addr.sll_ifindex=getindex(d_socket, interface);
  addr.sll_halen=ETHER_ADDR_LEN;
  addr.sll_protocol=htons(ETH_P_IP);
  memcpy(&addr.sll_addr, mac.c_str(), 6);
  sendPacket(ippacket, addr); 

}


void RawUDPListener::sendPacket(const std::string& ippacket, const struct sockaddr_ll& addr)
{
  if(sendto(d_socket, ippacket.c_str(), ippacket.size(), 0, (struct sockaddr*) &addr, sizeof(addr)) < 0)
    unixDie("sending packet");
}


uint16_t ip_checksum(const void* vdata,size_t length) {
    // Cast the data pointer to one that can be indexed.
    const char* data=(char*)vdata;

    // Initialise the accumulator.
    uint32_t acc=0xffff;

    // Handle complete 16-bit blocks.
    for (size_t i=0;i+1<length;i+=2) {
        uint16_t word;
        memcpy(&word,data+i,2);
        acc+=ntohs(word);
        if (acc>0xffff) {
            acc-=0xffff;
        }
    }

    // Handle any partial block at the end of the data.
    if (length&1) {
        uint16_t word=0;
        memcpy(&word,data+length-1,1);
        acc+=ntohs(word);
        if (acc>0xffff) {
            acc-=0xffff;
        }
    }

    // Return the checksum in network byte order.
    return htons(~acc);
}

string parseMac(const std::string& in)
{
  unsigned int parts[6];
  if(sscanf(in.c_str(),"%02x:%02x:%02x:%02x:%02x:%02x",
         &parts[0],
         &parts[1],
         &parts[2],
         &parts[3],
         &parts[4],
            &parts[5]) != 6) {
    throw std::runtime_error("Input '"+in+"' does not look like MAC address. Remove quotes?");
  }

  string ret;
  for(int n=0; n<6; ++n)
    ret.append(1, (char)parts[n]);

  return ret;
}

bool g_syslog{true};
bool g_console{true};

int main(int argc, char** argv)
try
{
  openlog("dnsfixer", LOG_PID | LOG_CONS, LOG_DAEMON);
  infolog("dnsfixer starting up");
  po::options_description desc("Allowed options");
  desc.add_options()
    ("help,h", "produce help message")
    ("input-interface", po::value<string>()->required(), "Interface to listen on")
    ("output-interface", po::value<string>()->required(), "Interface to forward non-blocked queries to")
    ("block-marker", po::value<string>()->required(), "IP address or CNAME to recognize blocking by")
    ("quiet", po::value<bool>()->default_value(true), "don't be too noisy")
    ("mac-gw", po::value<string>()->required(), "MAC address of default gw")
    ("recursor", po::value<string>()->required(), "Backend recursor IP:port address");

  std::ifstream configfile("dnsfixer.conf");
  if(configfile) {
    po::store(po::parse_config_file(configfile, desc), g_vm);
  }
  
  po::store(po::command_line_parser(argc, argv).options(desc).run(), g_vm);
  po::notify(g_vm);

  if (g_vm.count("help")) {
    cout<<desc<<endl;
    return EXIT_SUCCESS;
  }

  
  
  reportAllTypes();
  string mac=parseMac(g_vm["mac-gw"].as<string>());
  RawUDPListener rul(53, g_vm["input-interface"].as<string>());
  string payload, packet;
  ComboAddress src, dst;
//  string mac("\x00\x0d\xb9\x3f\x80\x18", 6);
//  string mac("\xb8\x27\xeb\x13\x0d\x73", 6);
  ComboAddress recursor(g_vm["recursor"].as<string>(), 53);


  int recsock = socket(AF_INET, SOCK_DGRAM, 0);
  if(recsock < 0)
    unixDie("Making socket to talk to recursor");
    

  if(connect(recsock, (struct sockaddr*)&recursor, recursor.getSocklen()) < 0)
    unixDie("Connecting to recursor");
  
  for(;;) {
    struct sockaddr_ll macsrc;
    if(rul.getPacket(&src, &dst, &macsrc, &payload, &packet)) {
      if(dst.sin4.sin_port != htons(53))
        continue;
      else {
        MOADNSParser mdp(payload);
        infolog("Received DNS query for %s|%s, rd=%d from %s to %s",
                mdp.d_qname.toString(),
                DNSRecordContent::NumberToType(mdp.d_qtype),
                mdp.d_header.rd,
                src.toStringWithPort(),
                dst.toStringWithPort());

        if(send(recsock, payload.c_str(), payload.size(), 0) < 0)
          unixDie("Sending query to recursor");
        char verdict[1500];
        int len=recv(recsock, verdict, sizeof(verdict), 0);
        if(len < 0)
          unixDie("Receiving answer from recursor");

        infolog("Actual recursor said");
        MOADNSParser rep(string(verdict, len));
        bool blocked=false;        
        for(const auto& a : rep.d_answers) {
          infolog("%s %s %s", a.first.d_name, DNSRecordContent::NumberToType(a.first.d_type), a.first.d_content->getZoneRepresentation());
          if((a.first.d_type == QType::A && a.first.d_content->getZoneRepresentation()==g_vm["block-marker"].as<string>()))
            blocked = true;
        }

        // send query to our normal nameserver, see what it does
        // if we get non-blocked answer, send on to internet
        // if we get blocked answer, send back blocked answer
        
        if(blocked) {
          infolog("Query was blocked by recursor");
          // now we need to pretend we are '1.2.3.4', the evil nameserver
          char p[packet.size()+1500];
          memcpy(p, packet.c_str(), packet.size());
          struct ip *iphdr = (struct ip*)p;
          struct udphdr *udphdr= (struct udphdr*)(p + 4 * iphdr->ip_hl);

          auto tmp1 = iphdr->ip_src;
          iphdr->ip_src= iphdr->ip_dst;
          iphdr->ip_dst = tmp1;
          
          auto tmp2 = udphdr->uh_sport;
          udphdr->uh_sport = udphdr->uh_dport;
          udphdr->uh_dport = tmp2;
          
          struct dnsheader* dh = (struct dnsheader*)verdict;
          dh->id = mdp.d_header.id;
          
          auto startpos = 4*iphdr->ip_hl + sizeof(struct udphdr);
          memcpy(p+startpos, verdict, len);

          iphdr->ip_len = htons(4*iphdr->ip_hl + sizeof(struct udphdr) + len);
          udphdr->uh_ulen = htons(sizeof(struct udphdr) + len);
          
          iphdr->ip_sum = 0;
          iphdr->ip_sum = ip_checksum(p, 4*iphdr->ip_hl); 
          
          udphdr->uh_sum = 0;
//          udphdr->uh_sum = ip_checksum(p+4*iphdr->ip_hl, ntohs(udphdr->uh_ulen));
          
          rul.sendPacket(string(p, startpos + len), macsrc);
          
        }
        else {
          // pass it on
          infolog("Query was not blocked, forwarding to internet");
          rul.sendPacket(packet, g_vm["output-interface"].as<string>(), mac);
        }
      }
      

    }
    else
      cout<<"Got error"<<endl;
  }
}
catch(std::exception& e)
{
  cerr<<"Error: "<<e.what()<<endl;
  return EXIT_FAILURE;
}
