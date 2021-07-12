# about counter
# https://cornell-pl.github.io/cs6114/lecture07.html
	it is impossible to read the value of a counter (which is an extern) in a p4 program. However the vlaue of a counter can be queried by the control plane. E.g. the simple_switch_CLI provides an command 'counter_read' that takes the name of a counter and an index, and returns the packet/byte counters associated with that counter. See example below
>>RUNTIMECMD: counter_read MyIngress.c 1
  MyIngress.c[1] = BmCounterValue(packets =1, bytes=59) //bmv2 counters keeps track of both packer and byte counters by default, even though the counter itself was created with counterType.packets
NOTE: In simple_switch_CLI, when you give command of e.g. "counter_read MyIngress.c 0", it will give the number of packets that came through ingress port 0. 
//Please also see on the link above, about 'direct counters'
