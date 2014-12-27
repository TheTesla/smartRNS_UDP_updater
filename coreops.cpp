

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


