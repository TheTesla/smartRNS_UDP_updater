/*  Copyright (C) 2014 Stefan Helmert <stefan.helmert@gmx.net>
    smartRNS configuration data
*/

#ifndef CONFIGURATION_H_INCLUDED
#define CONFIGURATION_H_INCLUDED

#include <vector>
#include <string>
#include <iostream>
#include "parse.h"

using namespace std;


typedef enum primenc_e
{
    PRIMENC_NOT_SPEC = -1,
    NO_PRIMENC  =  0,
    BASE16      = 16,
    BASE32      = 32,
    BASE64      = 64,
    BASE85      = 85
} primenc_et;

typedef enum urienc_e
{
    URIENC_NOT_SPEC = -1,
    NO_URIENC   =   0,
    SHA_1       =   1,
    SHA_2       = 256,
    SHA_224     = 224,
    SHA_256     = 256,
    SHA_384     = 384,
    SHA_512     = 512,
    SHA_3       =   3
} urienc_et;

typedef enum contenc_e
{
    CONTENC_NOT_SPEC = -1,
    NO_CONTENC  =   0,
    AES_128     =   128
} contenc_et;


typedef struct smartrns_conf_s
{
    string version;
    primenc_et uriprimenc;
    urienc_et urienc;
    uint32_t subdomlen;
    primenc_et contprimenc;
    contenc_et contenc;
    string salt;
    bool passwd;
    bool subdom;
} smartrns_conf_t;





urienc_et uriencstr2enum(string str);
string enum2uriencstr(urienc_et enc);
contenc_et contencstr2enum(string str);
string enum2contencstr(contenc_et enc);
smartrns_conf_t smartrnsvec2smartrnsconf(vector<keyval_t> smartrnsvec);
smartrns_conf_t confvec2smartrnsconf(vector<keyval_t> confvec);
smartrns_conf_t txtrec2smartrnsconf(string txtstr);
void print_smartrns_config(smartrns_conf_t conf);


#endif // CONFIGURATION_H_INCLUDED
