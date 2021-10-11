/*
 * Compile with:
 * clang -o networkScope ...
 *
 * 4 command line arguments passed.
 * Argument 0: ./networkScope
 * Argument 1: aaa
 * Argument 2: bbb
 * Argument 3: ccc
 */

#include <stdio.h>
#include <string.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include "utility.h"
#include "dns.h"
#include "tcp.h"

/*
 * TODO:
 * 1) Build OpenSSL for x86 (https://cutecoder.org/programming/compile-open-ssl-apple-silicon/)
 * 1.1) https://stackoverflow.com/questions/14150772/compiling-and-linking-openssl-on-ubuntu-vs-osx
 * 2) Link libcrypto and libssl into this program and verify it by reading vars from OpenSSL
 * 3) Move to a build script for linking and building
 * 4) Start build network scope proxy.
 *
 *
 */

void print_header() {

	unsigned int major = OPENSSL_version_major();
    unsigned int minor = OPENSSL_version_minor();

	printf("##########################################\n");
	printf("#         NetScope                       #\n");
	printf("#     Dependencies:                      #\n");
	printf("#     OpenSSL version %d.%d                #\n", major, minor);
	printf("##########################################\n");

}

void print_help() {
	printf("NetScope Usage: \n");
}


int main(int argc, char *argv[]) {

	const char * url, *tlsVersion, *dnsAddr;
	Connection *connection = malloc(sizeof(Connection));
	connection->ipVersion = 4;
	printf("Argument Size: %d\n", argc);
	// Print Header
	print_header();

	// Example usage:
	// netScope -url https://agnosticdev.com -p 443 -tls 1.2
	// netScope -url https://ipv6-test.com -p 443 -tls 1.2 -v6

	if (argc > 0) {
		for (int i = 0; i < argc; i ++) {
			printf("Argument %d: %s\n", i, argv[i]);
			if ((strcmp(argv[i], "-help") == 0)) {
				// Run help here.  This is for future.
				// print_help();
			}
			// Detect if printing help is needed
			if ((strcmp(argv[i], "-url") == 0) && ((i + 1) < argc)) {
				url = argv[i + 1];
			}
			if ((strcmp(argv[i], "-p") == 0) && ((i + 1) < argc)) {
				connection->dstPort = atoi(argv[i + 1]);
			}
			if ((strcmp(argv[i], "-tls") == 0) && ((i + 1) < argc)) {
				tlsVersion = argv[i + 1];
			}
			if ((strcmp(argv[i], "-v6") == 0)) {
				connection->ipVersion = 6;
			}
		}
	}
	printf("IP Version: %d\n", connection->ipVersion);
	printf("URL: %s\n", url);
	printf("PORT: %d\n", connection->dstPort);
	printf("TLS: %s\n", tlsVersion);

	// 2. Do DNS on the URL (log this traffic) even in DoH and DoT (similar to wireshark)
	perform_dns_for(url, connection);

	//connection->ipVersion = getIPVersion(dnsAddr);
	printf("DST ADDR %s, DST PORT: %d / SRC ADDR %s, SRC PORT %d with IP version %d, TLS %s\n", connection->dstIP, connection->dstPort, connection->srcIP, connection->srcPort, connection->ipVersion, tlsVersion);

	// 3. Setup a TCP connection. (log this behavior) and get a socket file descriptor
	int sfd = setup_tcp_connection(connection, tlsVersion);

	// 4. Setup TLS. (log this traffic) (similar to openssl_connect)
	// Start TLS connection logic
	int attachTLSStatus = attach_tls_to_descriptor(sfd, tlsVersion);
	if (attachTLSStatus == -1) {
		printf("Error setting up TLS, tearing down TCP connection\n");
		close(sfd);
		free(connection);
		return 0;
	}

	// 5. Do HTTP here.
	printf("DO HTTP on the FD\n");

	shut_down_tls();
	close(sfd);
	free(connection);
	return 0;
}