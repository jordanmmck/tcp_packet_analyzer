#define MAX_STR_LEN 20
#define MAX_NUM_CONNECTION 1000

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <pcap.h>
#include <netinet/tcp.h>

#include "../include/tcp_structs.h"
#include "../include/tcp_analyzer.h"

void problem_pkt(struct timeval ts, const char *reason){
	fprintf(stderr, "%s: %s\n", timestamp_string(ts), reason);
}

void too_short(struct timeval ts, const char *truncated_hdr){
	fprintf(stderr, "packet with timestamp %s is truncated and lacks a full %s\n",
		timestamp_string(ts), truncated_hdr);
}
