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

void update_data_out(struct connection *curr){
	long long int first_seq, final_out;

	// total data successfully sent is final ack - first seq
	first_seq = curr->rtt_ary_src[1].seq_num;
	final_out = curr->rtt_ary_dst[curr->rtt_ary_dst_len-1].ack_num;
	curr->ttl_bytes_out = (int)(final_out-first_seq-curr->src_rst_count);
	curr->ttl_bytes = curr->ttl_bytes_in+curr->ttl_bytes_out;
}

void get_conn_stats(struct connection *root, int *total_conns, int *complete_conns, int *rst_conns, int *open_conns){
	*total_conns = 0;
	*complete_conns = *rst_conns = *open_conns = 0;
	struct connection *curr = root;
	*total_conns = get_conn_count(root);

	// iterate through connections, update values
	while(curr != NULL){
		*complete_conns += curr->is_complete;
		if(curr->is_rst)
			*rst_conns=*rst_conns+1;
		curr = curr->next;
	}
	*open_conns = *total_conns-*complete_conns;
}

void get_dur_stats(struct connection *root, double *min_duration, double *max_duration, double *mean_duration){
	*min_duration = *max_duration = *mean_duration = 0;
	double sum = 0;
	int count = 0;
	struct connection *curr = root;

	while(curr != NULL){
		if(curr->is_complete == 1){	
			// set initial values
			if(count==0){
				*min_duration = *max_duration = *mean_duration = curr->duration;
			}
			// set min, max
			if(curr->duration<*min_duration)
				*min_duration=curr->duration;
			if(curr->duration>*max_duration)
				*max_duration=curr->duration;
			
			sum+=curr->duration;
			count++;
		}
		curr = curr->next;
	}
	*mean_duration = sum/count;
}

void get_rtt_stats(struct connection *root, double *min, double *max, double *mean){
	struct connection *curr = root;
	struct round_trip *src;
	struct round_trip *dst;
	int rtt_count = 0;
	double sum = 0;
	int count=0;

	// iterate through each connection
	while(curr!=NULL){
		// if connection is incomplete, skip
		if(curr->is_complete != 1){ curr = curr->next; continue;}

		int src_len = curr->rtt_ary_src_len;
		int dst_len = curr->rtt_ary_dst_len;
		src = curr->rtt_ary_src;
		dst = curr->rtt_ary_dst;
		
		// two passes, one for outgoing, one for incoming
		int m;
		for(m=0; m<=1; m++){

			// iterate through outgoing packets 
			int i;
			for(i=0; i< src_len; i++){
				
				// if this packet occurs later (duplicate) then skip
				if(is_duplicate((src+i),src_len)) continue;

				// iterate through incoming looking for match
				int j;
				for(j=0; j<dst_len; j++){
					if((src+i)->time>(dst+j)->time) continue;
					int size = (src+i)->size;
					if((src+i)->syn) size = 1;
					
					// match found
					if(rtt_match((src+i),(dst+j),size)){
						double time_interval = (dst+j)->time-(src+i)->time;						
						// first RTT time, set min, max, sum
						if(sum==0) *min = *max = sum = time_interval;
						if(time_interval < *min) *min = time_interval;
						if(time_interval > *max) *max = time_interval;
						sum += time_interval;	
						rtt_count++;
						break;
					}
				}
			}
			// swtich pointers for second (incoming) pass
			dst = curr->rtt_ary_src;
			src = curr->rtt_ary_dst;
			src_len = curr->rtt_ary_dst_len;
			dst_len = curr->rtt_ary_src_len;
		}
		curr = curr->next;
	}	
	*mean = (double)sum/rtt_count;
}

int is_duplicate(struct round_trip *src, int ary_size){
	int i;
	for(i=1; i<ary_size; i++)
		if(src->seq_num==(src+i)->seq_num && src->ack_num==(src+i)->ack_num)
			return 1;
	return 0;
}

int rtt_match(struct round_trip *src, struct round_trip *dst, int size){
	if(src->seq_num + size == dst->ack_num && src->ack_num == dst->seq_num && dst->fin==0){
		return 1;
	}
	return 0;
}

void get_packet_stats(struct connection *root, int *min_packets, int *max_packets, int *mean_packets){
	*min_packets = *max_packets = *mean_packets = 0;
	int sum = 0, count = 0;
	struct connection *curr = root;

	while(curr != NULL){
		if(curr->is_complete==1){
			// set intial values
			if(count==0){
				*min_packets = *max_packets = *mean_packets = curr->ttl_packets;
			}
			// set min, max
			if(curr->ttl_packets<*min_packets)
				*min_packets=curr->ttl_packets;
			if(curr->ttl_packets>*max_packets)
				*max_packets=curr->ttl_packets;
			
			sum+=curr->ttl_packets;
			count++;
		}
		curr = curr->next;
	}
	*mean_packets = sum/count;
}

void get_winsize_stats(struct connection *root, uint16_t *min_win_size, uint16_t *max_win_size, uint16_t *mean_win_size){
	*min_win_size = *max_win_size = *mean_win_size = 0;
	int sum = 0, packet_count = 0;
	struct connection *curr = root;

	while(curr != NULL){
		if(curr->is_complete==1){
			// set intial values
			if(packet_count==0){
				*min_win_size = curr->min_win_size;
				*max_win_size = curr->max_win_size;
			}
			// set min, max
			if(curr->min_win_size<*min_win_size)
				*min_win_size=curr->min_win_size;
			if(curr->max_win_size>*max_win_size)
				*max_win_size=curr->max_win_size;
			
			sum += curr->sum_win_size;
			packet_count += curr->ttl_packets;
		}
		curr = curr->next;
	}
	*mean_win_size = (uint16_t)(sum/packet_count);
}

int get_conn_count(struct connection *root){
	struct connection *curr = root;
	int count = 0;

	while(curr!=NULL){
		count++;
		curr = curr->next;
	}
	return count;
}


