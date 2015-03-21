
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
    vector<string> encvec;
    string key;
    size_t pos = 0;
    int i = 0;

    vector<vector<string>> alldecvecs;
    vector<vector<keyval_t>> allkeyvalvecs;
    vector<smartrns_conf_t> allconfs;
    vector<smartrns_data_t> alldatas;
    vector<string> alldomains;

    //UDPiface udp("127.0.0.1", 7334);
    UDPiface udp("178.63.154.91", 7334);

    if(2==argc){
        request = argv[1]; // the domain to query
    }else if((3==argc) | (4==argc)){
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
        cout << "USAGE: smartRNS_UDP_updater [options] YourName@smartrns.net" << endl << endl;
        cout << "options: n - allow unencrypted mode" << endl;
        cout << "         v - verbose: show all cycles" << endl;
        cout << "         s - show data-/config-structure" << endl;
        cout << "         r - raw (decrypted TXT records)" << endl;
        cout << "         c - show config" << endl;
        cout << "         w - write entries" << endl;
        cout << "         d - delete entries" << endl << endl;
        cout << "    Copyright (C) 2014 - 2015 Stefan Helmert <stefan.helmert@gmx.net>" << endl;
        cout << endl;
        cout << "Try out writing entries! Please ensure at first that upper level entry has a valid configuration." << endl;
        cout << endl;
        cout << "EXAMPLE: smartRNS_UDP_updater w myName@test.smartrns.net \"smartrns.data{entry{type=email;email=myEmail@myDomain.com;push=1;}}\"" << endl;
        cout << endl;
        return 0;
    }


    smartquery query(request, n);

    // everything after the @
    domain = uritop(request, &pos);
    key = domain;

    // show recursive resolve steps
    for(i=0;i<query.get_no_recursions()-1;i++){ // recursion over all subdomains
        if(v){
            if(r) {
                cout << "REQUEST" << endl << endl << "    " << query.get_domain(i) << endl << endl;
                print_decvec(query.get_decvec(i));
            }
            if(s) print_key_val_vec(query.get_keyvalvec(i));   // output
            if(c) print_smartrns_config(query.get_conf(i));    // output
            print_smartrns_data(query.get_data(i));      // output
        }
    }

    // show result
    if(r) {
        cout << "REQUEST" << endl << endl << "    " << query.get_domain(-1) << endl << endl;
        print_decvec(query.get_decvec(-1));
    }
    if(s) print_key_val_vec(query.get_keyvalvec(-1));   // output
    if(c) print_smartrns_config(query.get_conf(-1));    // output
    print_smartrns_data(query.get_data(-1));      // output

    // update entries
    if(d){
        udp.senddata(update_packet_del(0x42, query.get_domain(-1)));
    }
    if(w){
        encvec.clear();
        encvec.push_back(record);
        key = request;
        encvec = encrypt(encvec, query.get_conf(-2).salt+key, query.get_conf(-2).contprimenc, query.get_conf(-2).contenc);
        udp.senddata(update_packet_add_s(0x42, query.get_domain(-1), encvec[0]));
    }





    return 0;
}
