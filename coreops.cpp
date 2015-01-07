

#include "coreops.h"

// get the right side of "@"
string uritop(string uri, size_t* pos)
{
    uri = '@' + uri;
    *pos = uri.find_last_of('@');
    return uri.substr(*pos+1);
}

// get the next subdomain-part, e. h. public.myname@smartrns.net -> get "myname" and then get "public"
string uripart(string uri, size_t* pos)
{
    size_t newpos;
    string partstr;
    uri = '.'+uri;
    newpos = uri.find_last_of('.', *pos-1);
    partstr = uri.substr(newpos+1, newpos - *pos);
    *pos = newpos;
    return partstr;
}

// tell the next domain to reuqest - in encrypted/converted form
string getdomain(string uri, size_t* pos, uint32_t subdomlen, primenc_et primenc, urienc_et urienc, string salt)
{
    string suburi;
    byte encdom[CryptoPP::SHA::DIGESTSIZE];
    suburi = uripart(uri, pos);

    if(NO_PRIMENC == primenc){
        if(NO_URIENC == urienc){
            return suburi;
        }
        nourienc(encdom, salt+uri.substr(*pos));
    }

    if(NO_URIENC == urienc){
        nourienc(encdom, salt+uri.substr(*pos));
    }else if(SHA_1 == urienc){
        sha1(encdom, salt+uri.substr(*pos));
    }else if(SHA_224 == urienc){
        sha224(encdom, salt+uri.substr(*pos));
    }else if(SHA_256 == urienc){
        sha256(encdom, salt+uri.substr(*pos));
    }else if(SHA_384 == urienc){
        sha384(encdom, salt+uri.substr(*pos));
    }else if(SHA_512 == urienc){
        sha512(encdom, salt+uri.substr(*pos));
    }else{
        cout << "getdomain() - secondary encoding not supported!" << endl;
        throw urienc;
        return "";
    }

    if(BASE16 == primenc){
        return base16enc(encdom, CryptoPP::SHA::DIGESTSIZE).substr(0,subdomlen);
    }else if(BASE32 == primenc){
        return base32enc(encdom, CryptoPP::SHA::DIGESTSIZE).substr(0,subdomlen);
    }else if(NO_PRIMENC == primenc){
        cout << "getdomain() - combination not supported! Hashed value must be primencoded!" << endl;
        throw primenc;
        return "";
    }else{
        cout << "getdomain() - primary encoding not supported!" << endl;
        throw primenc;
        return "";
    }

    return "";
}

smartquery::smartquery(string URI, bool no_enc)
{
    string domain, request, options;
    vector<string> decvec;
    smartrns_conf_t conf, resetconf;
    smartrns_data_t data;
    vector<keyval_t> keyvalvec;
    string key;
    vector<string> txts;
    size_t pos = 0;
    resetconf.contenc = NO_CONTENC;
    resetconf.contprimenc = NO_PRIMENC;
    conf = resetconf;

    n = no_enc;
    uri = URI;
    request = uri;

    // everything after the @
    domain = uritop(request, &pos);
    key = domain;

    // now before the @
    while(1){ // recursion over all subdomains

        // get the DNS records
        txts = getTXTrecs(domain, MAXRECS);

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

        alldecvecs.push_back(decvec);
        allkeyvalvecs.push_back(keyvalvec);
        allconfs.push_back(conf);
        alldatas.push_back(data);
        alldomains.push_back(domain);

        if(0==pos) break; // no remaining subdomain

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
}

smartquery::~smartquery()
{

}

string smartquery::get_uri()
{
    return uri;
}

bool smartquery::get_unenc_was_allowed()
{
    return n;
}

vector<vector<string>> smartquery::get_alldecvecs()
{
    return alldecvecs;
}

vector<vector<keyval_t>> smartquery::get_allkeyvalvecs()
{
    return allkeyvalvecs;
}

vector<smartrns_conf_t> smartquery::get_allconfs()
{
    return allconfs;
}

vector<smartrns_data_t> smartquery::get_alldatas()
{
    return alldatas;
}

vector<string> smartquery::get_alldomains()
{
    return alldomains;
}


vector<string> smartquery::get_decvec(int32_t i)
{
    if(0 > i){
        return alldecvecs[alldecvecs.size()+i];
    }
    return alldecvecs[i];
}

vector<keyval_t> smartquery::get_keyvalvec(int32_t i)
{
    if(0 > i){
        return allkeyvalvecs[allkeyvalvecs.size()+i];
    }
    return allkeyvalvecs[i];
}

smartrns_conf_t smartquery::get_conf(int32_t i)
{
    if(0 > i){
        return allconfs[allconfs.size()+i];
    }
    return allconfs[i];
}

smartrns_data_t smartquery::get_data(int32_t i)
{
    if(0 > i){
        return alldatas[alldatas.size()+i];
    }
    return alldatas[i];
}

string smartquery::get_domain(int32_t i)
{
    if(0 > i){
        return alldomains[alldomains.size()+i];
    }
    return alldomains[i];
}

size_t smartquery::get_no_recursions()
{
    return alldomains.size();
}


