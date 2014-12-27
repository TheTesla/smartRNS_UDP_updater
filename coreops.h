
/*  Copyright (C) 2014 Stefan Helmert <stefan.helmert@gmx.net>
    smartRNS-Query-Client
*/

#ifndef COREOPS_H_INCLUDED
#define COREOPS_H_INCLUDED

#include <iostream>

#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>
#include <string>
#include <vector>
#include "configuration.h"
#include "data.h"
#include "parse.h"
#include "crypto.h"
#include "dnsquery.h"

using namespace std;

string uritop(string uri, size_t* pos);
string uripart(string uri, size_t* pos);
string getdomain(string uri, size_t* pos, uint32_t subdomlen, primenc_et primenc, urienc_et urienc, string salt);




#endif // COREOPS_H_INCLUDED
