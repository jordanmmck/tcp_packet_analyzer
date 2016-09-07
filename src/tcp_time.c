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

double get_time(struct timeval zero_time, struct timeval ts){
	long int_part = 1000000*((int)ts.tv_sec-(int)zero_time.tv_sec);
	long dec_part = (int)ts.tv_usec-(int)zero_time.tv_usec;
	return (double)(int_part+dec_part)/1000000;
}

const char *timestamp_string(struct timeval ts){
	static char timestamp_string_buf[256];

	sprintf(timestamp_string_buf, "%d.%06d",
		(int) ts.tv_sec, (int) ts.tv_usec);

	return timestamp_string_buf;
}