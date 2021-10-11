#include "tcp.h"


// Setup the initial TCP connection
int setup_tcp_connection(Connection *connection, const char *tlsVersion) {

	// Datagram to represent the packet
	char dataBuffer[4096];
	struct sockaddr_in dstAddress;
	struct sockaddr_in6 dst6Address;

	// Define the address type and the type of sockaddr being used for the destination.
	int arpaInetAddrVersion = AF_INET;
	dstAddress.sin_family = arpaInetAddrVersion;
	dstAddress.sin_addr.s_addr = inet_addr(connection->dstIP);
	dstAddress.sin_port = htons(connection->dstPort);

	// Note that IPv6 may seem like it's not supported on a local network, if this is seen
	// try using it from a hotspot, like a mobile device.  This should produce a positive result.
	if (connection->ipVersion == 6) {
		arpaInetAddrVersion = AF_INET6;
		dst6Address.sin6_flowinfo = 0;
		dst6Address.sin6_family = AF_INET6;
		if (inet_pton(AF_INET6, connection->dstIP, &(dst6Address.sin6_addr)) == 1) {
			printf("Converted Destination IP %s to IPv6 address structure\n", connection->dstIP);
		}
		dst6Address.sin6_port = htons(connection->dstPort);
	}

	printf("-------------- TCP Connection -------------\n");

	// For now we are assuming TCP; this will also need to be adjusted for Linux I'm sure.
	int sfd = socket(arpaInetAddrVersion, SOCK_STREAM, IPPROTO_TCP);
	if (sfd == -1) {
	    printf("Could not create socket.  Exiting \n");
	    exit(0);
	}
	printf("Socket file descriptor created \n");
	printf("Connecting over TCP to %s\n" , connection->dstIP);

	// Connect via IPv4 or IPv6 (TODO: figure out a better to connect this way)
	if (connection->ipVersion == 6) {
		if (connect(sfd, (struct sockaddr*)&dst6Address, sizeof(dst6Address)) != 0) {
			printf("IPv6 TCP socket connection failed to %s\n", connection->dstIP);
			exit(0);
	    }
	    printf("IPv6 TCP socket connected to %s\n", connection->dstIP);
	} else {
		if (connect(sfd,(struct sockaddr*)&dstAddress, sizeof(dstAddress)) != 0) {
	        printf("IPv4 TCP socket connection failed to %s\n", connection->dstIP);
	        exit(0);
	    }
	    printf("IPv4 TCP socket connected to %s\n", connection->dstIP);
	}

	printf("-------------- END TCP Connection -------------\n");
	return sfd;
}

