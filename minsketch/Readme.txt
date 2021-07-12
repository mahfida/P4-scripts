With mincount.p4, number of packets of a flow crossing a switch are counted.
The p4 program uses the min count sketch to do the counting.
Packets from same flow are identified by IP source address, IP destination address,
source port address, destination port address and the transport protocol type i.e. tcp/udp.
The minimum count sketch uses three hash tables, i.e. registers, to store the count of packets
of a flow. Indices of the three hash tables are computed using hash algorithms with different
seeds but same flowid. Counter at the three indices are incremented when a packet of the flow crosses
the switch. For count of the number of the packets per flow, value of the counter with minimum value among
the three counters is identified. We store the value of the minimum count of a flow in a metadata variable. 
Since simple_switch_CLI can only access the state-full parameters i.e. counters/registers, to be able to access
the metadata variable we log it i.e. log_msg{} within the apply block of Egress control. 
Note to enable logging, you have to pass --log-console command to switch start. See the link below for enabling logging
https://github.com/nsg-ethz/p4-learning/blob/master/documentation/debugging-and-troubleshooting.md
