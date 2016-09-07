#ifndef TCP_ANALYZER_H
#define TCP_ANALYZER_H

// initialize new connection, returns pointer to connection struct
struct connection *set_conn(struct tcphdr *tcp, char *ip_src, char *ip_dst, 
	double time, unsigned int data_size);

// update existing connection
void update_conn(struct connection *conn, struct tcphdr *tcp, double time, 
	unsigned int data_size, int is_outgoing);

// check validity of packet and sends for sorting
void dump_TCP_packet(const unsigned char *packet, struct timeval ts, 
	unsigned int capture_len, struct connection **root);

// sorts packet into new or existing connection, returns if sorted into 
// existing connection or used to create new connection
int sort_packet(struct connection *curr, struct tcphdr *tcp, char *ip_src, char *ip_dst, 
	uint16_t port_src, uint16_t port_dst, double time, unsigned int data_size);

// prints connection header, calls for connection stats to be updated and calls
// for connection stats to be printed
void get_conn_summary(struct connection *root);

// prints connection stats
void print_conn(struct connection *conn, int conn_count);

// calls for all connection stats to be updated, then prints all stats
void get_gen_summary(struct connection *root);


// updates data sent for connection
void update_data_out(struct connection *curr);

// updates overall stats for all connections
void get_conn_stats(struct connection *root, int *total_conns, int *complete_conns,
 int *rst_conns, int *open_conns);

// updates connection duration stats
void get_dur_stats(struct connection *root, double *min_duration, double *max_duration, 
	double *mean_duration);

// updates overall RTT time stats
void get_rtt_stats(struct connection *root, double *min, double *max, double *mean);

// checks if packet occurs later in stream
int is_duplicate(struct round_trip *src, int ary_size);

// returns 1 if packets are a valid RTT match
int rtt_match(struct round_trip *src, struct round_trip *dst, int size);

// updates overall packet stats
void get_packet_stats(struct connection *root, int *min_packets, int *max_packets, 
	int *mean_packets);

// updates overall window size stats
void get_winsize_stats(struct connection *root, uint16_t *min_win_size, 
	uint16_t *max_win_size, uint16_t *mean_win_size);

// returns total number of connections
int get_conn_count(struct connection *root);


// takes timeval struct and returns time since zero time as a double
double get_time(struct timeval zero_time, struct timeval ts);

// returns timestamp string
const char *timestamp_string(struct timeval ts);


// prints error message for invalid packet
void problem_pkt(struct timeval ts, const char *reason);

// prints error message for too short packet
void too_short(struct timeval ts, const char *truncated_hdr);

#endif
