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

int main(int argc, char *argv[]){
	const unsigned char *packet;
	struct pcap_pkthdr header;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct connection *root = 0;
	struct connection **root_ptr = &root;
	pcap_t *pcap;

	++argv; --argc;
	
	if ( argc != 1 ){
		fprintf(stderr, "program requires one argument, the trace file to dump\n");
		exit(1);
	}
	pcap = pcap_open_offline(argv[0], errbuf);
	if (pcap == NULL){
		fprintf(stderr, "error reading pcap file: %s\n", errbuf);
		exit(1);
	}

	// send all packets to be sorted into connections
	while ((packet = pcap_next(pcap, &header)) != NULL){
		dump_TCP_packet(packet, header.ts, header.caplen, root_ptr);
	}
	// print connection summary
	get_conn_summary(root);
	// print general summary
	get_gen_summary(root);

	return 0;
}

void dump_TCP_packet(const unsigned char *packet, struct timeval ts, unsigned int capture_len, struct connection **root_ptr){
	static struct timeval zero_time;
	unsigned int IP_header_length, data_size;
	char ip_src[MAX_STR_LEN], ip_dst[MAX_STR_LEN];
	uint16_t port_src, port_dst;
	double time;
	struct ip *ip;
	struct tcphdr *tcp;
	struct connection *curr;

	if (capture_len < sizeof(struct ether_header)){
		too_short(ts, "Ethernet header");
		return;
	}
	// skip over ethernet header
	packet += sizeof(struct ether_header);
	capture_len -= sizeof(struct ether_header);
	if (capture_len < sizeof(struct ip)){ 
		too_short(ts, "IP header");
		return;
	}
	ip = (struct ip*) packet;
	IP_header_length = ip->ip_hl * 4;
	if (capture_len < IP_header_length){ 
		too_short(ts, "IP header with options");
		return;
	}
	if (ip->ip_p != IPPROTO_TCP){
		problem_pkt(ts, "non-tcp packet");
		return;
	}
	// skip over IP header
	packet += IP_header_length;
	capture_len -= IP_header_length;
	if (capture_len < 20){
		too_short(ts, "tcp header");
		return;
	}

	tcp = (struct tcphdr*) packet;	
	data_size = capture_len - tcp->th_off*4;
	strcpy(ip_src,inet_ntoa(ip->ip_src));
	strcpy(ip_dst,inet_ntoa(ip->ip_dst));
	port_src = ntohs(tcp->th_sport);
	port_dst = ntohs(tcp->th_dport);
	
	// set root and zero time
	if(*root_ptr==NULL){
		zero_time = ts;
		time = 0;
		*root_ptr = set_conn(tcp, ip_src, ip_dst, time, data_size);
		return;
	}
	curr = *root_ptr;
	time = get_time(zero_time, ts);
	int is_sorted = 0;

	// check packet against existing connections
	while(1){
		if(is_sorted = sort_packet(curr, tcp, ip_src, ip_dst, port_src, port_dst, time, data_size))
			return;
		curr = curr->next;
	};
}

int sort_packet(struct connection *curr, struct tcphdr *tcp, char *ip_src, char *ip_dst, uint16_t port_src, uint16_t port_dst, double time, unsigned int data_size){
	
	// packet belongs to connection as outgoing
	if(strcmp(ip_src,curr->ip_src)==0 && strcmp(ip_dst,curr->ip_dst)==0
		&& port_src==curr->port_src && port_dst==curr->port_dst){
		update_conn(curr,tcp,time,data_size,1);
		return 1;
	
	// packet belongs to connection as incoming
	}if(strcmp(ip_src,curr->ip_dst)==0 && strcmp(ip_dst,curr->ip_src)==0
		&& port_src==curr->port_dst && port_dst==curr->port_src){
		update_conn(curr,tcp,time,data_size,0);
		return 1;
	
	// packet is first of new connection
	}if(curr->next == NULL){
		curr->next = set_conn(tcp,ip_src,ip_dst,time,data_size);
		return 1;
	
	}else{
		return 0;
	}
}

void get_conn_summary(struct connection *root){
	struct connection *curr = root;
	int conn_count = get_conn_count(root);

	printf("\nA) Total number of connections: %d\n\n", conn_count);
	printf("-----------------------------\n");
	printf("\nB) Connection details:\n\n");

	conn_count = 1;
	while(curr != NULL){
		update_data_out(curr);
		print_conn(curr, conn_count);
		curr = curr->next;
		conn_count++;
	}
	printf("+++++++++++++++++++++++++++++\n");
	printf("\n-----------------------------\n");
}

void print_conn(struct connection *conn, int conn_count){

	// print basic connection stats
	printf("+++++++++++++++++++++++++++++\n");
	printf("Connection %d:\n", conn_count);
	printf("Source Address: %s\n", conn->ip_src);
	printf("Destination Address: %s\n", conn->ip_dst);
	printf("Source Port: %d\n", conn->port_src);
	printf("Destination Port: %d\n", conn->port_dst);
	printf("Status: S%dF%d\n", conn->syn_count,conn->fin_count);
	
	// print completed connection stats
	if(conn->is_complete==1){
		printf("Start Time: %.3f\n", conn->starting_time);
		printf("End Time: %.3f\n", conn->ending_time);
		printf("Duration: %.3f\n", conn->duration);
		printf("Packets Sent: %d\n", conn->ttl_packets_out);
		printf("Packets Received: %d\n", conn->ttl_packets_in);
		printf("Total Packets: %d\n", conn->ttl_packets);
		printf("Bytes Sent: %d\n", conn->ttl_bytes_out);
		printf("Bytes Received: %d\n", conn->ttl_bytes_in);
		printf("Total Bytes: %d\n", conn->ttl_bytes);
	}
	printf("END\n");	
}

void get_gen_summary(struct connection *root){
	int ttl_conns, cmpt_conns, rst_conns, open_conns;
	double min_dur, max_dur, mean_dur, min_rtt, max_rtt, mean_rtt;
	int min_pcks, max_pcks, mean_pcks;
	uint16_t min_win_sz, max_win_sz, mean_win_sz;

	// call all helper functions to set values
	get_conn_stats(root, &ttl_conns, &cmpt_conns, &rst_conns, &open_conns);
	get_dur_stats(root, &min_dur, &max_dur, &mean_dur);
	get_rtt_stats(root, &min_rtt, &max_rtt, &mean_rtt);
	get_packet_stats(root, &min_pcks, &max_pcks, &mean_pcks);
	get_winsize_stats(root, &min_win_sz, &max_win_sz, &mean_win_sz);

	printf("\nC) General:\n\n");
	printf("Total number of complete TCP connections: %d\n", cmpt_conns);
	printf("Number of reset TCP connections: %d\n", rst_conns);
	printf("Number of TCP connections still open upon end of capture: %d\n", ttl_conns-rst_conns);
	printf("\n-----------------------------\n\n");
	
	printf("D) Complete TCP connections:\n\n");
	printf("Minimum time durations: %.3f\n", min_dur);
	printf("Mean time durations: %.3f\n", mean_dur);
	printf("Maximum time durations: %.3f\n\n", max_dur);

	printf("Minimum RTT values including both send/received: %.3f\n", min_rtt);
	printf("Mean RTT values including both send/received: %.3f\n", mean_rtt);
	printf("Maximum RTT values including both send/received: %.3f\n\n", max_rtt);
	
	printf("Minimum number of packets including both send/received: %d\n", min_pcks);
	printf("Mean number of packets including both send/received: %d\n", mean_pcks);
	printf("Maximum number of packets including both send/received: %d\n\n", max_pcks);
	
	printf("Minimum receive window sizes including both send/received: %d\n", (int)min_win_sz);
	printf("Mean receive window sizes including both send/received: %d\n", (int)mean_win_sz);
	printf("Maximum receive window sizes including both send/received: %d\n", (int)max_win_sz);

	printf("\n-----------------------------\n");
}



