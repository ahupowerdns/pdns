#include "rawudp.hh"
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
#include <net/ethernet.h> /* the L2 protocols */
#include "dnsrecords.hh"

StatBag S;

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

bool RawUDPListener::getPacket(std::string* packet)
{
  char buffer[1500];
  ComboAddress remote;
  remote.sin6.sin6_family=AF_INET6;
  socklen_t remlen = sizeof(remote);
  int res=recvfrom(d_socket, buffer, sizeof(buffer), 0, (struct sockaddr*)&remote, &remlen);
  if(res < 0)
    return false;
  packet->assign(buffer, res);
  return true;
}

bool RawUDPListener::getPacket(ComboAddress* src, ComboAddress* dst, std::string* payload, std::string* whole)
{
  string packet;
  if(!getPacket(&packet))
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
  memcpy(&addr.sll_addr, mac.c_str(), 6); //  00:0d:b9:3f:80:18
  if(sendto(d_socket, ippacket.c_str(), ippacket.size(), 0, (struct sockaddr*) &addr, sizeof(addr)) < 0)
    unixDie("sending packet");
}

int main()
{
  reportAllTypes();
  RawUDPListener rul(53, "nonbt");
  string payload, packet;
  ComboAddress src, dst;
  string mac("\x00\x0d\xb9\x3f\x80\x18", 6);
  
  for(;;) {
    if(rul.getPacket(&src, &dst, &payload, &packet)) {
      if(dst.sin4.sin_port != htons(53))
        cout<<"NOT DNS QUERY: ";
      else {
        MOADNSParser mdp(payload);
        cout<<"Query for "<<mdp.d_qname<<" | "<<DNSRecordContent::NumberToType(mdp.d_qtype)<<endl;

        rul.sendPacket(packet, "eth0", mac);
      }
      
      cout<<"Got "<<payload.size()<<" bytes from "<<src.toStringWithPort()<<" to "<<dst.toStringWithPort()<<endl;
      cout<<makeHexDump(payload)<<endl;
    }
    else
      cout<<"Got error"<<endl;
  }
}
