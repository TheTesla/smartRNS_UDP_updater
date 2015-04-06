#!/bin/sh
ls *.cpp | xargs g++ -std=c++11 -lcryptopp -lresolv -o bin/Release/smartRNS_UDP_updater
