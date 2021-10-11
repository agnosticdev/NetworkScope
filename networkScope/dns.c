#include "dns.h"

void perform_dns_for(const char * hostname, Connection *connection) {

	const char *address = "N/A";
	char *service = "https";
	struct addrinfo *result, *rp;
	struct addrinfo hints = {0};
	struct sockaddr_in *dst4Address;
	struct sockaddr_in6 *dst6Address;
	struct sockaddr_in src4Address;
	struct sockaddr_in6 src6Address;
	int sfd = -1, error;
	char dstBuf[64] = {0}; // TODO Look at dialing this in for IPv6
	char srcBuf[64] = {0};

	// Refactor hints addrinfo for linux
    hints.ai_family =  (connection->ipVersion == 4) ? AF_INET : AF_INET6;    
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_flags = AI_PASSIVE;

	error = getaddrinfo(hostname, service, &hints, &result);
	if (error) {
		printf("A failure took place while getting address info\n");
		exit(0);
	}

	printf("-------------- DNS Resolution -------------\n");
	printf("(DNS) -WAS- found for %s\n", hostname);
	for (rp = result; rp != NULL; rp = rp->ai_next) {
		int finished = 0;

	    sfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
	    if (sfd == -1) {
	    	printf("Could not connect socket\n");
	        continue;
	    }

		memset(&dstBuf, 0, 64);
		memset(&srcBuf, 0, 64);
		if (rp->ai_family == AF_INET) {
			// Get the destination IPv4 address
			dst4Address = (struct sockaddr_in *)rp->ai_addr;
	      	inet_ntop(AF_INET, &(dst4Address->sin_addr), dstBuf, sizeof(dstBuf));
	      	printf("(DNS) Destination address %s\n", dstBuf);
	      	
	      	copy_at_legth(dstBuf, connection->dstIP, sizeof(dstBuf));

	      	// Get the source IPv4 address
		    socklen_t src4AddrLen = sizeof(src4Address);
		    int e = getsockname(sfd, (struct sockaddr*) &src4Address, &src4AddrLen);
		    const char *srcPTR = inet_ntop(AF_INET, &src4Address.sin_addr, srcBuf, sizeof(srcBuf));
		    if (srcPTR == NULL) {
		    	printf("(DNS) errorno %d and strerror: %s", errno, strerror(errno));
		    	return;
		    } 

		    connection->srcPort = src4Address.sin_port;
		    copy_at_legth(srcBuf, connection->srcIP, sizeof(srcBuf));

		    printf("(DNS) Source address %s and port %d\n", connection->srcIP, connection->srcPort);
		    connection->ipVersion = 4;

		    // In the event that there are multiple results for result then break 
		    // on the first destination address for now. 
		    if (strlen(dstBuf) == 0) {
		    	finished = 1;
		    }

		} else {
			// Get the destination IPv6 address
			dst6Address = (struct sockaddr_in6 *)rp->ai_addr;
			inet_ntop(AF_INET6, &(dst6Address->sin6_addr), dstBuf, sizeof(dstBuf));
			printf("(DNS) Destination address %s\n", dstBuf);
			
			copy_at_legth(dstBuf, connection->dstIP, sizeof(dstBuf));
			// TODO: DOUBLE Check this logic for the IPv6 local address

			// Get the source IPv6 address
			socklen_t src6AddrLen = sizeof(src6Address);
		    int e = getsockname(sfd, (struct sockaddr*) &src6Address, &src6AddrLen);
		    const char *srcPTR = inet_ntop(AF_INET6, &src6Address.sin6_addr, srcBuf, sizeof(srcBuf));
		    if (srcPTR == NULL) {
		    	printf("(DNS) errorno %d and strerror: %s", errno, strerror(errno));
		    	return;
		    } 

			connection->srcPort = src6Address.sin6_port;
			copy_at_legth(srcBuf, connection->srcIP, sizeof(srcBuf));
		    printf("(DNS) Source address %s and port %d\n", connection->srcIP, connection->srcPort);


			// Set the IP Version to IPv6
			connection->ipVersion = 6;

		    // In the event that there are multiple results for result then break 
		    // on the first destination address for now. 
		    if (strlen(dstBuf) == 0) {
		    	finished = 1;
		    }
		}

	    close(sfd);
	    if (finished == 1) {
	    	break;
	    }
	}
	printf("------------ End DNS Resolution -----------\n");
	freeaddrinfo(result);
}