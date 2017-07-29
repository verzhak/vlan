
#ifndef ALL_HPP
#define ALL_HPP

#include <cstdio>
#include <string>
#include <vector>
#include <signal.h>
#include <arpa/inet.h>
#include <pcap.h>

using namespace std;

#define throw_ \
{\
	fprintf(stderr, "Error in %d %s\n", __LINE__, __FILE__);\
	throw 0;\
}

#define throw_if(cond)\
	if((cond))\
		throw_;

#define throw_null(ptr) throw_if((ptr) == NULL)

#endif

