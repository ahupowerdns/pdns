#pragma once
#include <string>
#include "iputils.hh"
#include <net/ethernet.h> /* the L2 protocols */

class RawUDPListener
{
public:
  RawUDPListener(int port, const std::string& interface = std::string());
  bool getPacket(std::string* packet, struct sockaddr_ll* addr);
  bool getPacket(ComboAddress* src, ComboAddress* dst, struct sockaddr_ll* addr, std::string* payload, std::string* whole=0);
  void sendPacket(const std::string& ippacket, const std::string& interface, const std::string& mac);  
  void sendPacket(const std::string& ippacket, const struct sockaddr_ll& addr);
  int getFD() const { return d_socket; }
private:
  int d_socket;

};
