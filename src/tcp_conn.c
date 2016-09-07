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

struct connection *set_conn(struct tcphdr *tcp, char *ip_src, char *ip_dst, double time, unsigned int data_size){
	struct connection *conn = (struct connection*)malloc(sizeof(struct connection));
	
	strcpy(conn->ip_src,ip_src);
	strcpy(conn->ip_dst,ip_dst);
	conn->port_src = ntohs(tcp->th_sport);
	conn->port_dst = ntohs(tcp->th_dport);

	// update initial round trip struct
	conn->rtt_ary_src[0].time = time;
	conn->rtt_ary_src[0].seq_num = (long long int)ntohl(tcp->th_seq);
	conn->rtt_ary_src[0].ack_num = (long long int)ntohl(tcp->th_ack);
	conn->rtt_ary_src[0].size = data_size;
	conn->rtt_ary_src[0].syn = (int)((tcp->th_flags & TH_SYN)>>1);
	conn->rtt_ary_src[0].fin = (int)((tcp->th_flags & TH_FIN));
	conn->rtt_ary_src_len = 1;

	// update connection stats
	conn->src_rst_count = (unsigned short)((tcp->th_flags & TH_RST)>>2);
	conn->is_rst = (unsigned short)((tcp->th_flags & TH_RST)>>2);
	conn->syn_count = (unsigned short)((tcp->th_flags & TH_SYN)>>1);
	conn->fin_count = (unsigned short)((tcp->th_flags & TH_FIN));
	conn->starting_time = time;
	conn->ttl_packets_out = conn->ttl_packets = 1;
	conn->max_win_size = conn->min_win_size = conn->sum_win_size = ntohs(tcp->th_win);

	return conn;
}

void update_conn(struct connection *conn, struct tcphdr *tcp, double time, unsigned int data_size, int is_outgoing){

	// packet is outgoing, update outgoing array
	if(is_outgoing==1){
		conn->ttl_packets_out++;
		conn->rtt_ary_src[conn->rtt_ary_src_len].time = time;
		conn->rtt_ary_src[conn->rtt_ary_src_len].seq_num = (long long int)ntohl(tcp->th_seq);
		conn->rtt_ary_src[conn->rtt_ary_src_len].ack_num = (long long int)ntohl(tcp->th_ack);
		conn->rtt_ary_src[conn->rtt_ary_src_len].fin = (int)((tcp->th_flags & TH_FIN));
		conn->rtt_ary_src[conn->rtt_ary_src_len].size = data_size;
		conn->rtt_ary_src_len++;
		if(((tcp->th_flags & TH_RST)>>2)){
			conn->src_rst_count++;
			conn->is_rst = 1;
		}
	// packet is incoming, update incoming array
	}else{
		conn->ttl_packets_in++;
		conn->ttl_bytes_in += data_size;
		conn->rtt_ary_dst[conn->rtt_ary_dst_len].time = time;
		conn->rtt_ary_dst[conn->rtt_ary_dst_len].seq_num = (long long int)ntohl(tcp->th_seq);
		conn->rtt_ary_dst[conn->rtt_ary_dst_len].ack_num = (long long int)ntohl(tcp->th_ack);
		conn->rtt_ary_dst[conn->rtt_ary_dst_len].fin = (int)((tcp->th_flags & TH_FIN));
		conn->rtt_ary_dst[conn->rtt_ary_dst_len].size = data_size;
		conn->rtt_ary_dst_len++;
		if(((tcp->th_flags & TH_RST)>>2))
				conn->is_rst = 1;
	}
	// update connection stats
	conn->ttl_packets++;
	conn->fin_count += (int)((tcp->th_flags & TH_FIN));
	conn->syn_count += (int)((tcp->th_flags & TH_SYN)>>1);
	
	// if connection is complete, get duration
	if(conn->syn_count > 0 && conn->fin_count > 0){
		conn->ending_time = time;
		conn->duration = time - conn->starting_time;
		conn->is_complete = 1;
	}
	// update win size stats
	if(ntohs(tcp->th_win) > conn->max_win_size)
		conn->max_win_size = ntohs(tcp->th_win);
	if(ntohs(tcp->th_win) < conn->min_win_size)
		conn->min_win_size = ntohs(tcp->th_win);
	conn->sum_win_size += ntohs(tcp->th_win);
}