#!/bin/sh

# This is a macOS variant only
DIR=`PWD`
echo "${DIR}/openssl/"

# Remove netScope to rebuild.
if test -x ${DIR}/netScope; then
	rm netScope
fi

# Build based on OS.
if [[ "$OSTYPE" == "darwin"* ]]; then
	# TODO: Move this to an Xcode project that use a framework to bundle up and load libcrypto and libssl.
	# DO NOT:  try and link libcrypto and libssl into an Xcode project like what is shown below as this will create 
	# a rouge rpath and Gatekeeper will reject you if you Developer ID submit.
	echo "macOS Detected"

	# local version
	clang -o netScope -I"${DIR}/openssl/" -I"${DIR}/openssl/include/" -I"${DIR}/openssl/apps/include/" -I"${DIR}/" -L"${DIR}/openssl/"  -lssl -lcrypto networkScope/main.c networkScope/dns.c networkScope/tcp.c networkScope/tls.c
	

elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
	echo "Linux Detected"
else 
	echo "No OS Detected"
fi

# Run netScope if created.
if test -x ${DIR}/netScope; then
	otool -L netScope
	# IPv6 (Make sure to test on a hotspot if your local network is not routing IPv6)
	#./netScope -url ipv6-test.com -p 443 -tls 1.2 -v6
	# IPv4
    ./netScope -url agnosticdev.com -p 443 -tls 1.2
else 
	echo "Nothing to run"
fi