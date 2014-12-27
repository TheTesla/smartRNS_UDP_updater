#ifndef UDPINTERFACE_H_INCLUDED
#define UDPINTERFACE_H_INCLUDED

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string>
#include <vector>

using namespace std;

class UDPiface
{
    public:
        UDPiface(string host, uint16_t port);
        ~UDPiface();
        int senddata(vector<uint8_t> datagram);

    private:
        int sockfd;
        struct sockaddr_in servaddr;

};

#endif // UDPINTERFACE_H_INCLUDED
