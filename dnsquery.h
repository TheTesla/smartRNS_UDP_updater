/*  Copyright (C) 2014 Stefan Helmert <stefan.helmert@gmx.net>
    smartRNS do the DNS query
*/

#ifndef DNSQUERY_H_INCLUDED
#define DNSQUERY_H_INCLUDED

#include <vector>
#include <string>
#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>

#define NSBUFSIZE 4096


using namespace std;

vector<string> getTXTrecs(string domain, uint32_t maxTXTs);


#endif // DNSQUERY_H_INCLUDED
