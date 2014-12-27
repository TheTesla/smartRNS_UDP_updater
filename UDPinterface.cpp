/*  Copyright (C) 2014 Stefan Helmert <stefan.helmert@gmx.net>
    smartRNS UDP interface part
*/

#include "UDPinterface.h"

UDPiface::UDPiface(string host, uint16_t port)
{
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = inet_addr(host.c_str());
    servaddr.sin_port = htons(port);

    sockfd = socket(AF_INET,SOCK_DGRAM,0);

}

UDPiface::~UDPiface()
{
}

int UDPiface::senddata(vector<uint8_t> datagram)
{
    return sendto(sockfd, datagram.data(), datagram.size(), 0, (struct sockaddr *)&servaddr, sizeof(servaddr));
}
