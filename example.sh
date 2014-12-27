#!/bin/bash

./bin/Debug/smartRNS_UDP_updater w stefan-helmert@team.smartrns.net "smartrns.conf{uriprimenc=base16;urienc=SHA-1;contprimenc=base64;contenc=AES-128;salt=42;subdomlen=35;version=test1;"
echo "wait for dns server\n"
for i in {1..120}
do
   sleep 1
   echo "$i"
done
./bin/Debug/smartRNS_UDP_updater w public.stefan-helmert@team.smartrns.net "smartrns.data{version=1.0;entry{type=phone;country=+49;prefix=177;number=8506921;usage=home;subtype=mobile;push=1;}}"
./bin/Debug/smartRNS_UDP_updater w public.stefan-helmert@team.smartrns.net "smartrns.data{entry{type=jabber;jabber=tesla@azapps.de;push=1;}}"
./bin/Debug/smartRNS_UDP_updater w public.stefan-helmert@team.smartrns.net "smartrns.data{entry{type=email;email=stefan@smartrns.net;push=1;}}"
echo "wait for dns server\n"
for i in {1..120}
do
   sleep 1
   echo "$i"
done

./bin/Debug/smartRNS_UDP_updater nrvcs public.stefan-helmert@team.smartrns.net

