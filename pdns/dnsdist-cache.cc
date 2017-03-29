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
#include "dnsdist.hh"
#include "dolog.hh"
#include "dnsparser.hh"
#include "dnsdist-cache.hh"

DNSDistPacketCache::DNSDistPacketCache(size_t maxEntries, uint32_t maxTTL, uint32_t minTTL, uint32_t tempFailureTTL, uint32_t staleTTL): d_maxEntries(maxEntries), d_maxTTL(maxTTL), d_tempFailureTTL(tempFailureTTL), d_minTTL(minTTL), d_staleTTL(staleTTL)
{
  /* we reserve maxEntries + 1 to avoid rehashing from occurring
     when we get to maxEntries, as it means a load factor of 1 */
  d_map.reserve(maxEntries + 1);
}

DNSDistPacketCache::~DNSDistPacketCache()
{
}

bool DNSDistPacketCache::cachedValueMatches(const CacheValue& cachedValue, const DNSName& qname, uint16_t qtype, uint16_t qclass, bool tcp)
{
  if (cachedValue.tcp != tcp || cachedValue.qtype != qtype || cachedValue.qclass != qclass || cachedValue.qname != qname)
    return false;
  return true;
}

void DNSDistPacketCache::insert(uint32_t key, const DNSName& qname, uint16_t qtype, uint16_t qclass, const char* response, uint16_t responseLen, bool tcp, uint8_t rcode)
{
  if (responseLen < sizeof(dnsheader))
    return;

  uint32_t minTTL;

  if (rcode == RCode::ServFail || rcode == RCode::Refused) {
    minTTL = d_tempFailureTTL;
    if (minTTL == 0) {
      return;
    }
  }
  else {
    minTTL = getMinTTL(response, responseLen);

    /* no TTL found, we don't want to cache this */
    if (minTTL == std::numeric_limits<uint32_t>::max()) {
      return;
    }

    if (minTTL > d_maxTTL) {
      minTTL = d_maxTTL;
    }

    if (minTTL < d_minTTL) {
      d_ttlTooShorts++;
      return;
    }
  }

  if (d_map.size() >= d_maxEntries) {
    return;
  }

  const time_t now = time(NULL);
  std::unordered_map<uint32_t,CacheValue>::iterator it;

  time_t newValidity = now + minTTL;
  CacheValue newValue;
  newValue.qname = qname;
  newValue.qtype = qtype;
  newValue.qclass = qclass;
  newValue.len = responseLen;
  newValue.validity = newValidity;
  newValue.added = now;
  newValue.tcp = tcp;
  newValue.value = std::string(response, responseLen);

  d_map.upsert(key, [&now, &qname, &qtype, &qclass, &tcp, &newValidity, &newValue, this](CacheValue& value) {
      bool wasExpired = value.validity <= now;
      /* in case of collision, don't override the existing entry
         except if it has expired */
      
      if (!wasExpired && !cachedValueMatches(value, qname, qtype, qclass, tcp)) {
        d_insertCollisions++;
        return;
      }
      
      /* if the existing entry had a longer TTD, keep it */
      if (newValidity <= value.validity) {
        return;
      }
      
      value = newValue;
    },  newValue);

}

bool DNSDistPacketCache::get(const DNSQuestion& dq, uint16_t consumed, uint16_t queryId, char* response, uint16_t* responseLen, uint32_t* keyOut, uint32_t allowExpired, bool skipAging)
{
  uint32_t key = getKey(*dq.qname, consumed, (const unsigned char*)dq.dh, dq.len, dq.tcp);
  if (keyOut)
    *keyOut = key;

  time_t now = time(NULL);
  time_t age;
  bool stale = false;
  int ret=-1;

  bool found=d_map.find_fn(key, [&](const CacheValue& value) {
    if (value.validity < now) {
      if ((now - value.validity) >= static_cast<time_t>(allowExpired)) {
        d_misses++;
        ret=false;
        return;
      }
      else {
        stale = true;
      }
    }
    
    if (*responseLen < value.len || value.len < sizeof(dnsheader)) {
      ret = false;
      return;
    }
                      
    /* check for collision */
    if (!cachedValueMatches(value, *dq.qname, dq.qtype, dq.qclass, dq.tcp)) {
      d_lookupCollisions++;
      ret=false;
      return;
    }
    
    memcpy(response, &queryId, sizeof(queryId));
    memcpy(response + sizeof(queryId), value.value.c_str() + sizeof(queryId), sizeof(dnsheader) - sizeof(queryId));
                      
    if (value.len == sizeof(dnsheader)) {
      /* DNS header only, our work here is done */
      *responseLen = value.len;
      d_hits++;
      ret = true;
      return;
    }
                      
    string dnsQName(dq.qname->toDNSString());
    const size_t dnsQNameLen = dnsQName.length();
    if (value.len < (sizeof(dnsheader) + dnsQNameLen)) {
      ret=false;
      return;
    }
                      
    memcpy(response + sizeof(dnsheader), dnsQName.c_str(), dnsQNameLen);
    if (value.len > (sizeof(dnsheader) + dnsQNameLen)) {
      memcpy(response + sizeof(dnsheader) + dnsQNameLen, value.value.c_str() + sizeof(dnsheader) + dnsQNameLen, value.len - (sizeof(dnsheader) + dnsQNameLen));
    }
    
    *responseLen = value.len;
    ret=true;
    if (!stale) {
      age = now - value.added;
    }
    else {
      age = (value.validity - value.added) - d_staleTTL;
    }
    
    if (!skipAging) {
      ageDNSPacket(response, *responseLen, age);
    }
    
    d_hits++;

    });
  if(!found) {
    d_misses++;
    return false;
  }
  return ret;
}
/* Remove expired entries, until the cache has at most
   upTo entries in it.
*/
void DNSDistPacketCache::purgeExpired(size_t upTo)
{
  time_t now = time(NULL);
  if (upTo >= d_map.size()) {
    return;
  }
  auto lt= d_map.lock_table();
  size_t toRemove = lt.size() - upTo;
  for(auto it = lt.begin(); toRemove > 0 && it != lt.end(); ) {
    const CacheValue& value = it->second;

    if (value.validity < now) {
        it = lt.erase(it);
        --toRemove;
    } else {
      ++it;
    }
  }
}

/* Remove all entries, keeping only upTo
   entries in the cache */
void DNSDistPacketCache::expunge(size_t upTo)
{
  if (upTo >= d_map.size()) {
    return;
  }

  auto lt = d_map.lock_table();
  size_t toRemove = lt.size() - upTo;
  auto beginIt = lt.begin();
  auto endIt = beginIt;
  std::advance(endIt, toRemove);
  for(; beginIt != endIt; )
    beginIt=lt.erase(beginIt);
}

void DNSDistPacketCache::expungeByName(const DNSName& name, uint16_t qtype, bool suffixMatch)
{
  auto lt=d_map.lock_table();
  
  for(auto it = lt.begin(); it != lt.end(); ) {
    const CacheValue& value = it->second;

    if ((value.qname == name || (suffixMatch && value.qname.isPartOf(name))) && (qtype == QType::ANY || qtype == value.qtype)) {
      it = lt.erase(it);
    } else {
      ++it;
    }
  }
}

bool DNSDistPacketCache::isFull()
{
  return (d_map.size() >= d_maxEntries);
}

uint32_t DNSDistPacketCache::getMinTTL(const char* packet, uint16_t length)
{
  return getDNSPacketMinTTL(packet, length);
}

uint32_t DNSDistPacketCache::getKey(const DNSName& qname, uint16_t consumed, const unsigned char* packet, uint16_t packetLen, bool tcp)
{
  uint32_t result = 0;
  /* skip the query ID */
  if (packetLen < sizeof(dnsheader))
    throw std::range_error("Computing packet cache key for an invalid packet size");
  result = burtle(packet + 2, sizeof(dnsheader) - 2, result);
  string lc(qname.toDNSStringLC());
  result = burtle((const unsigned char*) lc.c_str(), lc.length(), result);
  if (packetLen < sizeof(dnsheader) + consumed) {
    throw std::range_error("Computing packet cache key for an invalid packet");
  }
  if (packetLen > ((sizeof(dnsheader) + consumed))) {
    result = burtle(packet + sizeof(dnsheader) + consumed, packetLen - (sizeof(dnsheader) + consumed), result);
  }
  result = burtle((const unsigned char*) &tcp, sizeof(tcp), result);
  return result;
}

string DNSDistPacketCache::toString()
{
  return std::to_string(d_map.size()) + "/" + std::to_string(d_maxEntries);
}

uint64_t DNSDistPacketCache::getEntriesCount()
{
  return d_map.size();
}
