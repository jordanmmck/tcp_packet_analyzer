INPUT = "input/sample-capture-file"
OUTPUT = "output/out.txt"

.c.o:
	gcc -g -c $?

all:
	@ gcc -o run src/tcp_analyzer.c src/tcp_conn.c src/tcp_error.c \
	src/tcp_time.c src/tcp_stats.c -lpcap 
	./run ${INPUT} > ${OUTPUT}