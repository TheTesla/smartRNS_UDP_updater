
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

#define MAXRECS 4


string uritop(string uri, size_t* pos);
string uripart(string uri, size_t* pos);
string getdomain(string uri, size_t* pos, uint32_t subdomlen, primenc_et primenc, urienc_et urienc, string salt);

class smartquery
{
    public:
        smartquery(string uri, bool no_enc = false);
        ~smartquery();
        string get_uri();
        bool get_unenc_was_allowed();
        vector<vector<string>> get_alldecvecs();
        vector<vector<keyval_t>> get_allkeyvalvecs();
        vector<smartrns_conf_t> get_allconfs();
        vector<smartrns_data_t> get_alldatas();
        vector<string> get_alldomains();

        vector<string> get_decvec(int32_t i);
        vector<keyval_t> get_keyvalvec(int32_t i);
        smartrns_conf_t get_conf(int32_t i);
        smartrns_data_t get_data(int32_t i);
        string get_domain(int32_t i);
        size_t get_no_recursions();
    private:
        string uri;
        bool n;
        vector<vector<string>> alldecvecs;
        vector<vector<keyval_t>> allkeyvalvecs;
        vector<smartrns_conf_t> allconfs;
        vector<smartrns_data_t> alldatas;
        vector<string> alldomains;

};

#endif // COREOPS_H_INCLUDED
