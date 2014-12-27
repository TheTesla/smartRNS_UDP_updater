
/*  Copyright (C) 2014 Stefan Helmert <stefan.helmert@gmx.net>
    smartRNS-Update-Client for UDP interface
*/


#include <iostream>

#include "configuration.h"
#include "data.h"
#include "parse.h"
#include "crypto.h"
#include "dnsquery.h"
#include "coreops.h"
#include "UDPinterface.h"



#define MAXRECS 4

vector<uint8_t> update_packet_clr(uint8_t seq, uint8_t cmd = 0xA1)
{
    vector<uint8_t> packet;

    packet.push_back(1); // protver
    packet.push_back(1); // prottype
    packet.push_back(seq); // seq-nr.
    packet.push_back(cmd); // command

    return packet;
}

vector<uint8_t> update_packet_del(uint8_t seq, string url, uint8_t cmd = 0xA4)
{
    vector<uint8_t> packet;
    uint32_t i;

    packet = update_packet_clr(seq, cmd);
    packet.push_back(url.size()/256);
    packet.push_back(url.size()%256);
    for(i=0;i<url.size();i++){
        packet.push_back(url[i]);
    }
    return packet;
}

vector<uint8_t> update_packet_add_s(uint8_t seq, string url, string data, uint8_t cmd = 0xA2)
{
    vector<uint8_t> packet;
    uint32_t i;

    packet = update_packet_del(seq, url, cmd);
    packet.push_back(data.size()/256);
    packet.push_back(data.size()%256);
    for(i=0;i<data.size();i++){
        packet.push_back(data[i]);
    }

    return packet;
}

vector<uint8_t> update_packet_add_l(uint8_t seq, string url, string data, string rtype, int32_t ttl, uint8_t cmd = 0xA3)
{
    vector<uint8_t> packet;
    uint32_t i;

    packet = update_packet_add_s(seq, url, data, cmd);
    for(i=0;i<6;i++){
        if(i>rtype.size()){
            packet.push_back(rtype[i]);
        }else{
            packet.push_back(0);
        }
    }
    packet.push_back(ttl/16777216);
    packet.push_back((ttl/65536)%256);
    packet.push_back((ttl/256)%256);
    packet.push_back(ttl%256);

    return packet;
}


int main(int argc, char *argv[])
{

    string domain, request, options, record;
    bool n, v, s, r, c, w, d;
    n = v = s = r = c = w = d = false; // allow unencrypted mode, verbose (show all recursion steps), show data structure, raw (show raw data), show configuration
    vector<string> decvec;
    vector<string> encvec;
    smartrns_conf_t conf, lastconf, resetconf;
    smartrns_data_t data;
    vector<keyval_t> keyvalvec;
    string key;
    size_t pos = 0;
    //UDPiface udp("127.0.0.1", 7334);
    UDPiface udp("178.63.154.91", 7334);

    resetconf.contenc = NO_CONTENC;
    resetconf.contprimenc = NO_PRIMENC;
    conf = resetconf;


    vector<string> txts;

    if(2==argc){
        request = argv[1]; // the domain to query
    }else if(3==argc | 4==argc){
        options = argv[1];
        if(std::string::npos != options.find_first_of('n')) n = true;
        if(std::string::npos != options.find_first_of('v')) v = true;
        if(std::string::npos != options.find_first_of('s')) s = true;
        if(std::string::npos != options.find_first_of('r')) r = true;
        if(std::string::npos != options.find_first_of('c')) c = true;
        if(std::string::npos != options.find_first_of('w')) w = true;
        if(std::string::npos != options.find_first_of('d')) d = true;
        request = argv[2];
        if(w){
            if(4==argc){
                record = argv[3];
            }else{
                cout << "Empty record written!" << endl;
            }
        }
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
        cout << "         c - show config" << endl;
        cout << "         w - write netries" << endl;
        cout << "         d - delete entries" << endl << endl;
        cout << "    Copyright (C) 2014 Stefan Helmert <stefan.helmert@gmx.net>" << endl;
        cout << endl;
        return 0;
    }


    // everything after the @
    domain = uritop(request, &pos);
    key = domain;

    // now before the @
    while(1){ // recursion over all subdomains


        // get the DNS records
        txts = getTXTrecs(domain, MAXRECS);
        lastconf = conf;

        decvec.clear();
        try{
            // do decryption of requestet DNS content
            decvec = decrypt(txts, conf.salt+key, conf.contprimenc, conf.contenc);
        }
        catch(const primenc_et& f){
            conf = resetconf;
            cout << "No content primary encoding set!" << endl << endl;
            break;
        }
        catch(const contenc_et& e){
            conf = resetconf;
            keyvalvec.clear();
            cout << "No content secondary encoding set!" << endl << endl;
            break;
        }

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
            key = request.substr(pos);
        }
        catch(const primenc_et& f){
            if(PRIMENC_NOT_SPEC == f){
                cout << "URI primary encoding of subdomain not specified in configuration, aborting!" << endl;
            }
            break;
        }
        catch(const urienc_et& e){
            if(URIENC_NOT_SPEC == e){
                cout << "URI secondary encoding of subdomain not specified in configuration, aborting!" << endl;
            }
            break;
        }

    }

    if(r) {
        cout << "REQUEST" << endl << endl << "    " << domain << endl << endl;
        print_decvec(decvec);
    }


    if(d){
        udp.senddata(update_packet_del(0x42, domain));
    }
    if(w){
        encvec.clear();
        encvec.push_back(record);
        key = request;
        encvec = encrypt(encvec, lastconf.salt+key, lastconf.contprimenc, lastconf.contenc);
        udp.senddata(update_packet_add_s(0x42, domain, encvec[0]));
    }
    if(s) print_key_val_vec(keyvalvec);   // output
    if(c) print_smartrns_config(conf);    // output

    print_smartrns_data(data);      // output




    return 0;
}
