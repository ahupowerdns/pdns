#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

// #include "version.hh"
#include "dnsparser.hh"
#include "misc.hh"

#include "sstuff.hh"
#include "dnswriter.hh"
#include "namespaces.hh"
#include "stubresolver.hh"
#include <stdint.h>

string g_security_message;
string g_secpollsuffix="secpoll.powerdns.com";

/** Do an actual secpoll for the current version
 * @param first bool that tells if this is the first secpoll run since startup
 */
void doSecPoll(bool first)
{
  if(g_secpollsuffix.empty())
    return;

  struct timeval now;
  gettimeofday(&now, 0);

  string version = "dnsdist-" + string(VERSION);
  string query = version.substr(0, 63) +".security-status."+g_secpollsuffix;

  if(*query.rbegin()!='.')
    query+='.';

  boost::replace_all(query, "+", "_");
  boost::replace_all(query, "~", "_");

  vector<DNSZoneRecord> ret;
  cout<<"query: "<<query<<endl;
  int res=stubDoResolve(DNSName(query), QType::TXT, ret);

  int security_status=0;
  cout<<"res: "<<res<<", "<<ret.size()<<"\n";
  if(!res && !ret.empty()) {
    auto record=getRR<UnknownRecordContent>(ret.begin()->dr)->d_record;
    string content((char*)&record[1]);
    cout<<"content: '"<<content<<"'\n";
    std::pair<string, string> split = splitField(content, ' ');

    security_status = std::stoi(split.first);
    g_security_message = split.second;

  }
  else {
    string pkgv(VERSION);
    if(pkgv.find("0.0.") != 0)
      cerr<<"Could not retrieve security status update for '" + pkgv + "' on '"+query+"', RCODE = "<< RCode::to_s(res)<<endl;
    else
      cerr<<"Not validating response for security status update, this is a non-release version."<<endl;
  }

  if(security_status == 1 && first) {
    cerr << "Polled security status of version "<<VERSION<<" at startup, no known issues reported: " <<g_security_message<<endl;
  }
  if(security_status == 2) {
    cerr<<"PowerDNS Security Update Recommended: "<<g_security_message<<endl;
  }
  else if(security_status == 3) {
    cerr<<"PowerDNS Security Update Mandatory: "<<g_security_message<<endl;
  }

  // S.set("security-status",security_status);

}
