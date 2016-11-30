#pragma once
#include <string>
#include "iputils.hh"

class RawUDPListener
{
public:
  RawUDPListener(int port, const std::string& interface = std::string());
  bool getPacket(std::string* packet);
  bool getPacket(ComboAddress* src, ComboAddress* dst, std::string* payload, std::string* whole=0);
  void sendPacket(const std::string& ippacket, const std::string& interface, const std::string& mac);  
private:
  int d_socket;

};
