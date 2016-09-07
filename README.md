
## TCP Traffic Analyzer


#### Author: Jordan McKinney

#### Course: CSC 361


### Overview

This project consists of a basic TCP packet analyzer written
in C. 

The program takes a capture file (.cap) as input and parses
the packets into connections. The program extracts information
about the connections represented by the packets, and prints
this data to stdout.


### Compilation/Execution

To compile and run the program with the included sample file
(sample-capture-file.cap) simply type 'make' into the command
line. The program will output to 'out.txt'. 

To run the program with a different input file type:

`make INPUT="myinputfile"`

To send the output to a different output file type:

`make OUTPUT="myoutput.txt"`

Both options can be combined as:

`make INPUT="myinputfile" OUTPUT="myoutput.txt"`


Note: There may be some small variation in the output from 
reference material. Most parameters have been checked carefully
against Wireshark and tuned accordingly, but the accuracy of 
some values was difficult to verify. I have tried very hard to 
think through the logic carefully, so while some values may
differ I think my approach is sound.


### Sources

The skeleton of tcp_analyzer.c was borrowed from the course
connex page. The error handling messages were also borrowed
from the course connex page.