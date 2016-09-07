struct round_trip{
	double time;					/*time packet received*/
	long long int seq_num;			
	long long int ack_num;
	int size;						
	int syn;
	int fin;
};

struct connection{
	char ip_src[MAX_STR_LEN];	 	/*source ip*/
	char ip_dst[MAX_STR_LEN]; 		/*destination ip*/
	uint16_t port_src; 				/*source port number*/
	uint16_t port_dst; 				/*destination port number*/
	int syn_count;					/*number of SYN flags*/
	int fin_count;					/*number of FIN flags*/
	int src_rst_count;				/*number of outgoing RST flags*/
	int is_rst;						/*1 if connection has been reset*/
	double starting_time;			
	double ending_time;
	double duration;
	int ttl_packets_out; 			/*number of packets sent by source*/
	int ttl_packets_in; 			/*number of packets sent by destination*/
	int ttl_packets;				/*total packets sent or received*/
	int ttl_bytes_out; 				/*total bytes sent by source*/
	int ttl_bytes_in; 				/*total bytes sent by destination*/
	int ttl_bytes;
	uint16_t max_win_size; 			/*max window size*/
	uint16_t min_win_size; 			/*min window size*/
	int sum_win_size;
	int rtt_ary_src_len; 			/*the size of the rtt_ary_src array*/
	int rtt_ary_dst_len; 			/*the size of the rtt_ary_dst array*/
	struct round_trip rtt_ary_src[MAX_NUM_CONNECTION]; 
	struct round_trip rtt_ary_dst[MAX_NUM_CONNECTION]; 
	int is_complete;				/*1 if connection is complete*/
	struct connection *next;
};