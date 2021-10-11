#include <stdlib.h>
#include <stdio.h>
#include <string.h>

// networkScope's version of a 5-tuple
#pragma once
struct netScopeConnection {
	int ipVersion;
	char srcIP[64];
	int srcPort;
	char dstIP[64];
	int dstPort;
};

typedef struct netScopeConnection Connection;

// Custom method to avoid using strcpy
static char * copy_at_legth(char *src, char *dst, size_t srcLegth) {
	if (srcLegth > 0) {
		size_t i;
		for (i = 0; i < srcLegth - 1 && src[i]; i++) {
               dst[i] = src[i];
		}
		dst[i] = '\0';
	}
	return dst;	
}