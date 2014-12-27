
/*  Copyright (C) 2014 Stefan Helmert <stefan.helmert@gmx.net>
    smartRNS-Query-Client
*/


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



int main(int argc, char *argv[])
{
    string domain, request, options;
    bool n, v, s, r, c;
    n = v = s = r = c = false; // allow unencrypted mode, verbose (show all recursion steps), show data structure, raw (show raw data), show configuration
    vector<string> decvec;
    smartrns_conf_t conf;
    smartrns_data_t data;
    vector<keyval_t> keyvalvec;
    size_t pos = 0;


    conf.contenc = NO_CONTENC;
    conf.contprimenc = NO_PRIMENC;

    vector<string> txts;

    if(2==argc){
        request = argv[1]; // the domain to query
    }else if(3==argc){
        options = argv[1];
        if(std::string::npos != options.find_first_of('n')) n = true;
        if(std::string::npos != options.find_first_of('v')) v = true;
        if(std::string::npos != options.find_first_of('s')) s = true;
        if(std::string::npos != options.find_first_of('r')) r = true;
        if(std::string::npos != options.find_first_of('c')) c = true;
        request = argv[2];
    }else{
        cout << endl;
        cout << "Please specify Domain to lookup!" << endl;
        cout << endl;
        cout << "This program is designed to query and decode smartRNS data over standard DNS." << endl << endl;
        cout << "USAGE: smartRNSclient [options] YourName@smartrns.net" << endl << endl;
        cout << "options: n - allow unencrypted mode" << endl;
        cout << "         v - verbose: show all cycles" << endl;
        cout << "         s - show data-/config-structure" << endl;
        cout << "         r - raw (decrypted TXT records)" << endl;
        cout << "         c - show config" << endl << endl;
        cout << "    Copyright (C) 2014 Stefan Helmert <stefan.helmert@gmx.net>" << endl;
        cout << endl;
        return 0;
    }


    // everything after the @
    domain = uritop(request, &pos);

    // now before the @
    while(1){ // recursion over all subdomains

        // get the DNS records
        txts = getTXTrecs(domain, MAXRECS);

        // do decryption of requestet DNS content
        decvec = decrypt(txts, conf.salt+request, conf.contprimenc, conf.contenc);
        // interprete the content
        keyvalvec = txtrec2keyvalvec(decvec);
        conf = smartrnsvec2smartrnsconf(keyvalvec);
        data = smartrnsvec2smartrnsdata(keyvalvec);

        if(!n){
            if(NO_URIENC == conf.urienc){
                cout << "No domain encryption used by server - break! Please use parameter 'n' to allow sending an unencrypted domain - This is not secure!" << endl;
                break;
            }
            if(NO_CONTENC == conf.contenc){
                cout << "No content encryption used by server - break! Please use parameter 'n' to allow receiving unencrypted data - This is not secure!" << endl;
                break;
            }
        }

        if(0==pos) break; // no remaining subdomain


        if(v){
            if(r) {
                cout << "REQUEST" << endl << endl << "    " << domain << endl << endl;
                print_decvec(decvec);
            }
            if(s) print_key_val_vec(keyvalvec);   // output
            if(c) print_smartrns_config(conf);    // output
            print_smartrns_data(data);      // output
        }

        // next subdomain
        try{
            domain = getdomain(request, &pos, conf.subdomlen, conf.uriprimenc, conf.urienc, conf.salt)+'.'+domain;
        }
        catch(const urienc_et& e){
            if(URIENC_NOT_SPEC){
                cout << "URI encoding of subdomain not specified in configuration, aborting!" << endl;
            }
            break;
        }
    }

    if(r) {
        cout << "REQUEST" << endl << endl << "    " << domain << endl << endl;
        print_decvec(decvec);
    }
    if(s) print_key_val_vec(keyvalvec);   // output
    if(c) print_smartrns_config(conf);    // output
    print_smartrns_data(data);      // output


    return 0;
}

