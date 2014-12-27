/*  Copyright (C) 2014 Stefan Helmert <stefan.helmert@gmx.net>
    smartRNS doing the cryptopart - hash, aes
*/

#ifndef CRYPTO_H_INCLUDED
#define CRYPTO_H_INCLUDED

#include <vector>
#include <string>
#include <crypto++/modes.h>
#include <crypto++/aes.h>
#include <crypto++/filters.h>
#include <crypto++/sha.h>
#include <crypto++/hex.h>
#include <crypto++/base64.h>
#include <crypto++/base32.h>
#include <crypto++/hex.h>


#include <iostream>
#include "configuration.h"


#define CIPHERLEN 128

using namespace std;
using namespace CryptoPP;

void nourienc(byte* digest, string arg);
void sha1(byte* digest, string arg);
void sha224(byte* digest, string arg);
void sha256(byte* digest, string arg);
void sha384(byte* digest, string arg);
void sha512(byte* digest, string arg);


string hashdomain(string request);

string base64enc(byte* enc, uint32_t len);
string base32enc(byte* enc, uint32_t len);
string base16enc(byte* enc, uint32_t len);


void base64dec(byte* dec, byte* base64arr, uint32_t len = CIPHERLEN*8/6+1);
void base32dec(byte* dec, byte* base32arr, uint32_t len = CIPHERLEN*8/5+1);
void base16dec(byte* dec, byte* base16arr, uint32_t len = CIPHERLEN*8/4+1);
void nodec(byte* dec, byte* nocod, uint32_t len = CIPHERLEN+1);


void base64dec(byte* dec, string base64str);
void base32dec(byte* dec, string base32str);
void base16dec(byte* dec, string base16str);
void nodec(byte* dec, string nocodstr);


void AESdec(byte* decpt, u_char* cipher, string keystr);
string AESdec(u_char* cipher, string keystr);
string b64AESdec(string b64cipher, string keystr);
string b32AESdec(string b32cipher, string keystr);
string b16AESdec(string b16cipher, string keystr);

vector<string> b64AESdec(vector<string> b64cipher, string keystr);
vector<string> b32AESdec(vector<string> b32cipher, string keystr);
vector<string> b16AESdec(vector<string> b16cipher, string keystr);

vector<string> decrypt (vector<string> cipher, string keystr, primenc_et contprimenc, contenc_et contsecenc);
void print_decvec(vector<string> decvec);
void AESenc(byte* encpt, u_char* clrtxt, string keystr);
void AESencs(u_char* encpt, string clrtxtstr, string keystr);
vector<string> encrypt (vector<string> clrtxt, string keystr, primenc_et contprimenc, contenc_et contsecenc);



#endif // CRYPTO_H_INCLUDED
