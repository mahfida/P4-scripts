// LIBRARIES
#include<core.p4>
#include<v1model.p4>

// IPV4 PROTOCOL TYPE FIELD
const bit<8> UDP_PROTOCOL = 0x11;
const bit<8> TCP_PROTOCOL = 0x06;

//ETHERNET PROTOCOL TYPE FIELD
const bit<16> TYPE_IPV4 = 0x800;

// SIZE OF THE HASH TABLES
const bit<32> HASH_TABLE_SIZE = 1024;

/**********************Data structure for Count Minimum sketch***********/
register<bit<32> >(HASH_TABLE_SIZE) hashtable1;
register<bit<32> >(HASH_TABLE_SIZE) hashtable2;
register<bit<32> >(HASH_TABLE_SIZE) hashtable3;


/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9> egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;


header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16> etherType;
}

header ipv4_t {
    bit<4> version;
    bit<4> ihl;
    bit<8> diffserv;
    bit<16> totalLen;
    bit<16> identification;
    bit<3> flags;
    bit<13> fragOffset;
    bit<8> ttl;
    bit<8> protocol;
    bit<16> hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4> dataOffset;
    bit<3> res;
    bit<3> ecn;
    bit<6> ctrl;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> plength;
    bit<16> checksum;
}

/* STRUCTS-------------------*/
struct headers {
    ethernet_t ethernet;
    ipv4_t ipv4;
    tcp_t tcp;
    udp_t udp;
}


//Matadata contain flow id and hash-address/index variables
// for the three hashes and counts  
struct metadata_t {
    
    // five tuple: FlowId
    bit<16> srcPort;
    bit<16> dstPort;

    bit<104> my_flowID;

    // hash index in row 1, row2 and row3
    bit<32> index1;
    bit<32> index2;
    bit<32> index3;

    // count in row 1, row2 and row3
    bit<32> count1;
    bit<32> count2;
    bit<32> count3;
    bit<32> count_min;
}

error { IPHeaderTooShort }

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/
// parsing of the headers (Ethernet, ipv4, tcp/udp)

parser MyParser(packet_in packet,
  		out headers hdr,
                inout metadata_t meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            UDP_PROTOCOL : parse_udp;
     	    TCP_PROTOCOL : parse_tcp;
            default : accept;
        }
    }

    state parse_udp {
        packet.extract(hdr.udp);
 	meta.srcPort = hdr.udp.srcPort;
        meta.dstPort = hdr.udp.dstPort;
        transition accept;
        }

    state parse_tcp {
        packet.extract(hdr.tcp);
 	meta.srcPort = hdr.tcp.srcPort;
        meta.dstPort = hdr.tcp.dstPort;
        transition accept;
    }
}


/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata_t meta) {
    apply {
	}
}
/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/
// When ingress port recieves a message it is transmitted to the egress port

control MyIngress(inout headers hdr, inout metadata_t meta,
                  inout standard_metadata_t standard_metadata) {

    action drop() {
        mark_to_drop(standard_metadata);
    }

    action packet_forward(egressSpec_t port) {
        standard_metadata.egress_spec = port;
	 hdr.ipv4.ttl = hdr.ipv4.ttl - 1;   
 	}


    table ipv4_static {
        key = {
             	hdr.ipv4.dstAddr: lpm;
              }
        actions = {
             	packet_forward;
             	drop;
	     	NoAction;
               }
        default_action = NoAction;
    }

   apply{
 		if(hdr.ipv4.isValid()){
 		ipv4_static.apply();}

 	}
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr, inout metadata_t meta,
                 inout standard_metadata_t standard_metadata) {

    // join the five tuples into FlowID
    action compute_flow_id () {
        meta.my_flowID[31:0]=hdr.ipv4.srcAddr;
        meta.my_flowID[63:32]=hdr.ipv4.dstAddr;
        meta.my_flowID[71:64]=hdr.ipv4.protocol;
        meta.my_flowID[87:72]=meta.srcPort;
        meta.my_flowID[103:88]=meta.dstPort;
    }

    // compute the index in each hash table
    action compute_index() {
        hash(meta.index1, HashAlgorithm.crc16, 10w0,
                {meta.my_flowID, 10w33}, 10w1023);
        hash(meta.index2, HashAlgorithm.crc16, 10w0,
                {meta.my_flowID, 10w202}, 10w1023);
        hash(meta.index3, HashAlgorithm.crc16, 10w0,
                {meta.my_flowID, 10w541}, 10w1023);
    }

    action compute_mincount(inout bit<32> mincnt, in bit<32> cnt1, in bit<32> cnt2, in bit<32> cnt3) {
        if(cnt1 < cnt2) {
            mincnt = cnt1;
        } else {
            mincnt = cnt2;
        }

        if(mincnt > cnt3) {
            mincnt = cnt3;
        }

    }

   action increment_count(){
  		// Read from the three register data structures
  		// values at the three indices, into the three count
  		// variables
                hashtable1.read(meta.count1, meta.index1);
                hashtable2.read(meta.count2, meta.index2);
                hashtable3.read(meta.count3, meta.index3);

                // update the three counters and write the updated
  		// values back to their respective positions
  		// in the three register data structutes
                hashtable1.write(meta.index1, meta.count1 + 1);
                hashtable2.write(meta.index2, meta.count2 + 1);
                hashtable3.write(meta.index3, meta.count3 + 1);
	}

	 apply {
			//compute flow id
                	compute_flow_id();
                	// compute hash indexes for each hash table
                	compute_index();
			// increment counter at the hash indexes of the hash tables
			increment_count();
			// compute min count for the flow table		
  			compute_mincount(meta.count_min, meta.count1, meta.count2, meta.count3);
  			//Display in log file the id and count
  			log_msg("flowid={}, mincount={}",{meta.my_flowID, meta.count_min});
            	}
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers hdr, inout metadata_t meta) {
     apply {
 update_checksum(
     hdr.ipv4.isValid(),
            { hdr.ipv4.version,
       hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
         packet.emit(hdr.ethernet);
            packet.emit(hdr.ipv4);
            packet.emit(hdr.tcp);
            packet.emit(hdr.udp);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
