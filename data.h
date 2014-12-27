/*  Copyright (C) 2014 Stefan Helmert <stefan.helmert@gmx.net>
    smartRNS content data
*/


#ifndef DATA_H_INCLUDED
#define DATA_H_INCLUDED

#include <vector>
#include <string>
#include <iostream>

#include "parse.h"

using namespace std;

typedef enum entrytype_e
{
    NO_ETYPE  = 0,
    PHONE_NR  = 1,
    EMAIL     = 2,
    ICQ       = 3,
    JABBER    = 4,

    ETYPE_NOT_SPEC = -1

} entrytype_et;


typedef enum subtype_e
{
    NO_SUBTYPE = 0,
    FIXED      = 1,
    MOBILE     = 2,
    PORTABLE   = 3,
    SAT        = 4,

    SUBTYPE_NOT_SPEC = -1

} subtype_et;

typedef enum usagetype_e
{
    NO_USAGETYPE = 0,
    HOME         = 1,
    WORK         = 2,
    PRIVAT       = 3,
    PUBLIC       = 4,

    USAGETYPE_NOT_SPEC = -1

} usagetype_et;

typedef enum state_e
{
    NO_STATE    = 0,
    ONLINE      = 1,
    OFFLINE     = 2,
    ACTIVE      = 3,
    INACTIVE    = 4,
    AVAILABLE   = 5,
    AWAY        = 6,

    STATE_NOT_SPEC = -1
} state_et;

typedef struct smartrns_data_entry_phone_s
{
    subtype_et subtype;
    usagetype_et usage;
    string country;
    string prefix;
    string number;
    string suffix;

} smartrns_data_entry_phone_t;

typedef struct smartrns_data_entry_email_s
{
    string email;

} smartrns_data_entry_email_t;

typedef struct smartrns_data_entry_icq_s
{
    uint64_t icq;

} smartrns_data_entry_icq_t;

typedef struct smartrns_data_entry_jabber_s
{
    string jabber;

} smartrns_data_entry_jabber_t;

typedef struct smartrns_data_entry_s
{
    string name;
    string comment;
    entrytype_et type;
    state_et state;
    void* entry;

} smartrns_data_entry_t;

typedef struct smartrns_data_s
{
    string version;
    string name;
    string comment;
    vector<smartrns_data_entry_t> entries;

} smartrns_data_t;

state_et str2state(string str);
string state2str(state_et sta);
entrytype_et str2entrytype(string str);
string entrytype2str(entrytype_et entr);
subtype_et str2subtype(string str);
string subtype2str(subtype_et subt);
usagetype_et str2usagetype(string str);
string usagetype2str(usagetype_et usage);
smartrns_data_t smartrnsvec2smartrnsdata(vector<keyval_t> smartrnsvec);
smartrns_data_t txtrec2smartrnsdata(string txtstr);
void print_smartrns_data(smartrns_data_t data);


#endif // DATA_H_INCLUDED
