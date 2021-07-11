With mincount.p4, number of packets of a flow crossing a switch are counted.
The p4 program uses the min count sketch to do the counting.
Packets from same flow are identified by IP source address, IP destination address,
source port address, destination port address and the transport protocol type i.e. tcp/udp.
The minimum count sketch uses three hash tables, i.e. registers, to store the count of packets
of a flow. Indeces of the three hash tables are calculated using the hash algorithms with different
seeds but same flowid. Counter at the three indexes are incremented when a packet of the flow crosses
the switch. For count of the number of the packets per flow, value of the counter with minimum value among
the three counters is identified.
