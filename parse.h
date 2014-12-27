/*  Copyright (C) 2014 Stefan Helmert <stefan.helmert@gmx.net>
    smartRNS parse/interprete configuration and data strings in TXT records
*/


#ifndef PARSE_H_INCLUDED
#define PARSE_H_INCLUDED

#include <vector>
#include <string>
#include <iostream>


using namespace std;

typedef struct keyval_s
{
    string key;
    string val;
} keyval_t;

vector<keyval_t> txtrec2keyvalvec(string txtstr);
void print_key_val_vec(vector<keyval_t> arg);
vector<keyval_t> txtrec2keyvalvec(vector<string> TXT);

#endif // PARSE_H_INCLUDED
