/*  Copyright (C) 2014 Stefan Helmert <stefan.helmert@gmx.net>
    smartRNS configuration data
*/

#include "configuration.h"

// get primary encoding type from configuration in DNS entry or domainname
primenc_et primencstr2enum(string str)
{
    if("NONE"       == str) return NO_PRIMENC;
    if("base16"     == str) return BASE16;
    if("base32"     == str) return BASE32; // for domainname, the last "=" must be cutted away
    if("base64"     == str) return BASE64; // not usable for domainname, because upper and lower case characters
    if("base85"     == str) return BASE85; // -> the same; not used yet
    return PRIMENC_NOT_SPEC;
}

// reverse function of primencstr2enum()
string enum2primencstr(primenc_et enc)
{
    if(NO_PRIMENC == enc) return "NONE";
    if(BASE16     == enc) return "base16";
    if(BASE32     == enc) return "base32";
    if(BASE64     == enc) return "base64";
    if(BASE85     == enc) return "base85";
    return "undefined";
}

// get hash function type for domain
urienc_et uriencstr2enum(string str)
{
    if("NONE"       == str) return NO_URIENC;
    if("SHA-1"      == str) return SHA_1;
    if("SHA-2"      == str) return SHA_2;
    if("SHA-224"    == str) return SHA_224;
    if("SHA-256"    == str) return SHA_256;
    if("SHA-3"      == str) return SHA_3;
    if("SHA-384"    == str) return SHA_384;
    if("SHA-512"    == str) return SHA_512;
    return URIENC_NOT_SPEC;
}

// reverse function of uriencstr2enum()
string enum2uriencstr(urienc_et enc)
{
    if(NO_URIENC        == enc) return "NONE";
    if(SHA_1            == enc) return "SHA-1";
    if(SHA_224          == enc) return "SHA-224";
    if(SHA_256          == enc) return "SHA-256";
    if(SHA_3            == enc) return "SHA-3";
    if(SHA_384          == enc) return "SHA-384";
    if(SHA_512          == enc) return "SHA-512";
    if(SHA_2            == enc) return "SHA-2";
    if(URIENC_NOT_SPEC  == enc) return "not specified";
    return "undefined";
}

// get cryptop algorithmus for content
contenc_et contencstr2enum(string str)
{
    if("NONE"           == str) return NO_CONTENC;
    if("AES-128"        == str) return AES_128;
    return CONTENC_NOT_SPEC;
}

// reverse function of contencstr2enum()
string enum2contencstr(contenc_et enc)
{
    if(NO_CONTENC           == enc) return "NONE";
    if(AES_128              == enc) return "AES-128";
    if(CONTENC_NOT_SPEC     == enc) return "not specified";
    return "undefined";
}

// get smartRNS configuration of subdomain (domainencoding, encryption, ...)
smartrns_conf_t smartrnsvec2smartrnsconf(vector<keyval_t> smartrnsvec)
{
    uint32_t i;
    string txt, txtstr;
    smartrns_conf_t smartrnsconf;

    smartrnsconf.version    = "";
    smartrnsconf.subdom     = false;
    smartrnsconf.passwd     = false;
    smartrnsconf.salt       = "";
    smartrnsconf.uriprimenc = PRIMENC_NOT_SPEC;
    smartrnsconf.urienc     = URIENC_NOT_SPEC;
    smartrnsconf.subdomlen  = 0;
    smartrnsconf.contprimenc= PRIMENC_NOT_SPEC;
    smartrnsconf.contenc    = CONTENC_NOT_SPEC;

    for(i=0;i<smartrnsvec.size();i++){
        if("smartrns.conf.version" == smartrnsvec[i].key){
            smartrnsconf.version = smartrnsvec[i].val;
        }else if("smartrns.conf.salt" == smartrnsvec[i].key){
            smartrnsconf.salt = smartrnsvec[i].val;
        }else if("smartrns.conf.uriprimenc" == smartrnsvec[i].key){
            smartrnsconf.uriprimenc = primencstr2enum(smartrnsvec[i].val);
        }else if("smartrns.conf.urienc" == smartrnsvec[i].key){
            smartrnsconf.urienc = uriencstr2enum(smartrnsvec[i].val);
        }else if("smartrns.conf.subdomlen" == smartrnsvec[i].key){
            smartrnsconf.subdomlen = atoi(smartrnsvec[i].val.c_str());
        }else if("smartrns.conf.passwd" == smartrnsvec[i].key){
            smartrnsconf.passwd = true;
        }else if("smartrns.conf.subdom" == smartrnsvec[i].key){
            smartrnsconf.subdom = true;
        }else if("smartrns.conf.contprimenc" == smartrnsvec[i].key){
            smartrnsconf.contprimenc = primencstr2enum(smartrnsvec[i].val);
        }else if("smartrns.conf.contenc" == smartrnsvec[i].key){
            smartrnsconf.contenc = contencstr2enum(smartrnsvec[i].val);
        }

    }

    return smartrnsconf;
}

// convert one TXT record to configuration (not used)
smartrns_conf_t txtrec2smartrnsconf(string txtstr)
{
    vector<keyval_t> smartrnsvec;

    smartrnsvec = txtrec2keyvalvec(txtstr);

    return smartrnsvec2smartrnsconf(smartrnsvec);
}

// show configuration
void print_smartrns_config(smartrns_conf_t conf)
{
    cout << endl;
    cout << "smartrns-config" << endl;
    cout << endl;
    cout << "  Version:           " << conf.version << endl;
    cout << "  salt             = " << conf.salt << endl;
    cout << "  subdomain-length = " << conf.subdomlen << endl;
    cout << "  uri-primencoding = " << enum2primencstr(conf.uriprimenc) << endl;
    cout << "  uri-encoding     = " << enum2uriencstr(conf.urienc) << endl;
    cout << "  cont.-prim.-enc. = " << enum2primencstr(conf.contprimenc) << endl;
    cout << "  content-encoding = " << enum2contencstr(conf.contenc) << endl;

    if(conf.subdom) cout << "  + Subdomain available!" << endl;
    if(conf.passwd) cout << "  + Please provide password!" << endl;

    cout << endl;

}

