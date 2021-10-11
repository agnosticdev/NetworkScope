# Network Scope

Lightweight network connection logger.  A similar mix between `openssl_connect` and `curl -v`.

## Goals

This project aims to perform the following:

1. Input a URL with headers and params.
2. Do reverse DNS on the URL (log this traffic)
3. Setup a TCP connection. (log this traffic)
4. Setup handshake. (log this traffic) (similar to openssl_connect) for example:
```
$ openssl s_client -showcerts -state -debug -connect www.agnosticdev.com:443 -servername www.agnosticdev.com
```

5. Transfer data via HTTP connection (decrypt this traffic)

## Usage

```
# Support v4
$ netScope -url https://agnosticdev.com -p 443 -tls 1.2

# Support v6
$ netScope -url https://ipv6-test.com -p 443 -tls 1.2 -v6
```


## Dependencies

OpenSSL. Build for Intel based Macs.  NOTE: this project assumes a locally built and compiled development version of OpenSSL. <br>
This 


```bash
# Clone OpenSSL
% git clone https://github.com/openssl/openssl.git
% cd openssl

# NOTE: This is configuring OpenSSL on macOS to use a custom directory for dyld to load the dylibs from.
# The reason this is being done is in case you want to customize OpenSSL in any way.
# Otherwise skip this step and install it in system default path of /usr/local/lib/
# % ./Configure darwin64-x86_64-cc -shared

% ./Configure darwin64-x86_64-cc -shared --prefix=/Users/username/path/to/project/NetworkScopeProject/openssl --openssldir=.

% make

# At this point check that the dylibs contain a load command from the directory above using otool
% otool -l libssl.3.dylib

# Load command 11
#          cmd LC_LOAD_DYLIB
#      cmdsize 112
#         name /Users/username/path/to/project/NetworkScopeProject/openssl/lib/libcrypto.3.dylib (offset 24)
#   time stamp 2 W 

# Make a /lib directory inside of openssl
mkdir lib

# Then copy libcrypto.3.dylib, libssl.dylib, and the engines directory inside of lib

# At this point clang should be able to build:
clang -o netScope -I"${DIR}/openssl/include/" -L"${DIR}/openssl/"  -lssl -lcrypto networkScope/main.c
```

