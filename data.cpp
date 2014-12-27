/*  Copyright (C) 2014 Stefan Helmert <stefan.helmert@gmx.net>
    smartRNS content data
*/


#include "data.h"

// get state of entry (e. g. mobile telefon is off)
state_et str2state(string str)
{
    if("none"       == str) return NO_STATE;
    if("online"     == str) return ONLINE;
    if("offline"    == str) return OFFLINE;
    if("active"     == str) return ACTIVE;
    if("inactive"   == str) return INACTIVE;
    if("available"  == str) return AVAILABLE;
    if("away"       == str) return AWAY;
    return STATE_NOT_SPEC;
}

// reverse function of str2state()
string state2str(state_et sta)
{
    if(NO_STATE   == sta) return "none";
    if(ONLINE     == sta) return "online";
    if(OFFLINE    == sta) return "offline";
    if(ACTIVE     == sta) return "active";
    if(INACTIVE   == sta) return "inactive";
    if(AVAILABLE  == sta) return "available";
    if(AWAY       == sta) return "away";
    return "undefined";
}

// get type of data entry
entrytype_et str2entrytype(string str)
{
    if("none"   == str) return NO_ETYPE;
    if("phone"  == str) return PHONE_NR;
    if("email"  == str) return EMAIL;
    if("icq"    == str) return ICQ;
    if("jabber" == str) return JABBER;
    return ETYPE_NOT_SPEC;
}

// reverse function of str2entrytype()
string entrytype2str(entrytype_et entr)
{
    if(NO_ETYPE == entr) return "none";
    if(PHONE_NR == entr) return "phone";
    if(EMAIL    == entr) return "email";
    if(ICQ      == entr) return "icq";
    if(JABBER   == entr) return "jabber";

    if(ETYPE_NOT_SPEC == entr) return "not specified";
    return "undefined";
}

// get the subtype of data entry, e. g. type=phone, subtype=mobile
subtype_et str2subtype(string str)
{
    if("none"       == str) return NO_SUBTYPE;
    if("fixed"      == str) return FIXED;
    if("mobile"     == str) return MOBILE;
    if("portable"   == str) return PORTABLE;
    if("sat"        == str) return SAT;
    return SUBTYPE_NOT_SPEC;
}

// reverse function of str2subtype()
string subtype2str(subtype_et subt)
{
    if(NO_SUBTYPE == subt) return "none";
    if(FIXED      == subt) return "fixed";
    if(MOBILE     == subt) return "mobile";
    if(PORTABLE   == subt) return "portable";
    if(SAT        == subt) return "sat";

    if(SUBTYPE_NOT_SPEC == subt) return "not specified";
    return "undefined";
}

// get usage type of data entry, e. g. telephone for WORK
usagetype_et str2usagetype(string str)
{
    if("none"   == str) return NO_USAGETYPE;
    if("home"   == str) return HOME;
    if("work"   == str) return WORK;
    if("privat" == str) return PRIVAT;
    if("public" == str) return PUBLIC;
    return USAGETYPE_NOT_SPEC;
}

// reverse function of str2usagetype()
string usagetype2str(usagetype_et usage)
{
    if(NO_USAGETYPE == usage) return "none";
    if(HOME         == usage) return "home";
    if(WORK         == usage) return "work";
    if(PRIVAT       == usage) return "privat";
    if(PUBLIC       == usage) return "public";

    if(USAGETYPE_NOT_SPEC == usage) return "not specified";
    return "undefined";
}

// extract smartrns.data from DNS entry
smartrns_data_t smartrnsvec2smartrnsdata(vector<keyval_t> smartrnsvec)
{
    smartrns_data_t data;
    smartrns_data_entry_t entry;
    smartrns_data_entry_phone_t phone;   // only used if entry.type = phone
    smartrns_data_entry_email_t email;   // only used if entry.type = email
    smartrns_data_entry_icq_t icq;       // only used if entry.type = icq
    smartrns_data_entry_jabber_t jabber; // only used if entry.type = jabber
    uint32_t i;

    for(i=0;i<smartrnsvec.size();i++){
        if("smartrns.data.version" == smartrnsvec[i].key){
            data.version = smartrnsvec[i].val;
        }else if("smartrns.data.comment" == smartrnsvec[i].key){
            data.comment = smartrnsvec[i].val;
        }else if("smartrns.data.name" == smartrnsvec[i].key){
            data.name = smartrnsvec[i].val;
        }else if("smartrns.data.entry.name" == smartrnsvec[i].key){
            entry.name = smartrnsvec[i].val;
        }else if("smartrns.data.entry.comment" == smartrnsvec[i].key){
            entry.comment = smartrnsvec[i].val;
        }else if("smartrns.data.entry.type" == smartrnsvec[i].key){
            entry.type = str2entrytype(smartrnsvec[i].val);
        }else if("smartrns.data.entry.state" == smartrnsvec[i].key){
            entry.state = str2state(smartrnsvec[i].val);
        }else if("smartrns.data.entry.country" == smartrnsvec[i].key){
            phone.country = smartrnsvec[i].val;
        }else if("smartrns.data.entry.prefix" == smartrnsvec[i].key){
            phone.prefix = smartrnsvec[i].val;
        }else if("smartrns.data.entry.number" == smartrnsvec[i].key){
            phone.number = smartrnsvec[i].val;
        }else if("smartrns.data.entry.suffix" == smartrnsvec[i].key){
            phone.suffix = smartrnsvec[i].val;
        }else if("smartrns.data.entry.usage" == smartrnsvec[i].key){
            phone.usage = str2usagetype(smartrnsvec[i].val);
        }else if("smartrns.data.entry.subtype" == smartrnsvec[i].key){
            phone.subtype = str2subtype(smartrnsvec[i].val);
        }else if("smartrns.data.entry.email" == smartrnsvec[i].key){
            email.email = smartrnsvec[i].val;
        }else if("smartrns.data.entry.icq" == smartrnsvec[i].key){
            icq.icq = atoll(smartrnsvec[i].val.c_str());
        }else if("smartrns.data.entry.jabber" == smartrnsvec[i].key){
            jabber.jabber = smartrnsvec[i].val;
        }else if("smartrns.data.entry.push" == smartrnsvec[i].key){
            if("1" == smartrnsvec[i].val){
                if(PHONE_NR == entry.type){
                    entry.entry = (void*) new smartrns_data_entry_phone_t;
                    *((smartrns_data_entry_phone_t*) entry.entry) = phone;
                }else if(EMAIL == entry.type){
                    entry.entry = (void*) new smartrns_data_entry_email_t;
                    *((smartrns_data_entry_email_t*) entry.entry) = email;
                }else if(ICQ == entry.type){
                    entry.entry = (void*) new smartrns_data_entry_icq_t;
                    *((smartrns_data_entry_icq_t*) entry.entry) = icq;
                }else if(JABBER == entry.type){
                    entry.entry = (void*) new smartrns_data_entry_jabber_t;
                    *((smartrns_data_entry_jabber_t*) entry.entry) = jabber;
                }
                data.entries.push_back(entry);
            }

        }

    }

    return data;
}

// convert one TXT record to smartRNS data
smartrns_data_t txtrec2smartrnsdata(string txtstr)
{
    vector<keyval_t> smartrnsvec;

    smartrnsvec = txtrec2keyvalvec(txtstr);

    return smartrnsvec2smartrnsdata(smartrnsvec);
}

// show data entries
void print_smartrns_data(smartrns_data_t data)
{
    uint32_t i;
    cout << endl;
    cout << "smartrns-data" << endl;
    cout << endl;
    cout << "  Name:           " << data.name << endl;
    cout << "  Version:        " << data.version << endl;
    cout << "  Comment:        " << data.comment << endl;
    cout << "  Entries (" << data.entries.size() << "): " << endl;
    for(i=0;i<data.entries.size();i++){
        cout.width(3);
        cout << i <<" Name:         " << data.entries[i].name << endl;
        cout << "    Comment:      " << data.entries[i].comment << endl;
        cout << "    Type:         " << entrytype2str(data.entries[i].type) << endl;
        cout << "    State:        " << state2str(data.entries[i].state) << endl;
        if(PHONE_NR == data.entries[i].type){
            cout << "    Phone (" << subtype2str(((smartrns_data_entry_phone_t*) data.entries[i].entry)->subtype) << "): " << ((smartrns_data_entry_phone_t*) data.entries[i].entry)->country << " " << ((smartrns_data_entry_phone_t*) data.entries[i].entry)->prefix << " " << ((smartrns_data_entry_phone_t*) data.entries[i].entry)->number << " " << ((smartrns_data_entry_phone_t*) data.entries[i].entry)->suffix << " (" << usagetype2str(((smartrns_data_entry_phone_t*) data.entries[i].entry)->usage) << ")"<< endl;
        }else if(ICQ == data.entries[i].type){
            cout << "    ICQ:          " << ((smartrns_data_entry_icq_t*) data.entries[i].entry)->icq << endl;
        }else if(EMAIL == data.entries[i].type){
            cout << "    E-Mail:       " << ((smartrns_data_entry_email_t*) data.entries[i].entry)->email << endl;
        }else if(JABBER == data.entries[i].type){
            cout << "    Jabber:       " << ((smartrns_data_entry_jabber_t*) data.entries[i].entry)->jabber << endl;
        }else if(NO_ETYPE == data.entries[i].type){
            cout << "    No Entrytype! " << endl;
        }else if(ETYPE_NOT_SPEC == data.entries[i].type){
            cout << "    Entrytype not specified! " << endl;
        }
        cout << endl;
    }
    cout << endl;
}
