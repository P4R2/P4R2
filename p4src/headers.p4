typedef bit<48> mac_addr_t;
typedef bit<32> ipv4_addr_t;


header ethernet_h {
    mac_addr_t dst_addr;
    mac_addr_t src_addr;
    bit<16> ether_type;
}

header ipv4_h {
    bit<4> version;
    bit<4> ihl;
    bit<6> diffserv;
    bit<2> ecn;
    bit<16> total_len;
    bit<16> identification;
    bit<1> rec;
    bit<2> flags;
    bit<13> frag_offset;
    bit<8> ttl;
    bit<8> protocol;
    bit<16> hdr_checksum;
    ipv4_addr_t src;
    ipv4_addr_t dst;
}

header tcp_h {
    bit<16> src_port;
    bit<16> dst_port;
    bit<32> seq_no;
    bit<32> ack_no;
    bit<4> data_offset;
    bit<4> res;
    bit<1> cwr;
    bit<1> ece;
    bit<1> urg;
    bit<1> ack;
    bit<1> psh;
    bit<1> rst;
    bit<1> syn;
    bit<1> fin;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgent_ptr;
}

header udp_h {
    bit<16> src_port;
    bit<16> dst_port;
    bit<16> hdr_lenght;
    bit<16> checksum;
}

header nc_h {
    bit<8> op;
    bit<32> key;
    bit<32> value;
}

header rr_h {
    bit<8>  time;
    bit<32> info;
    bit<9> port;
    bit<7> padding;
}

header tunnel_h {
    bit<16> dst_id;
}

header cacl_h {
    bit<32> opA;
    bit<32> opB;
    bit<32> res;
    bit<8> op;
}

struct header_t {
    ethernet_h ethernet;
    ipv4_h ipv4;
    tunnel_h tunnel;
    cacl_h cacl;
    tcp_h tcp;
    udp_h udp;
    nc_h nc;
    rr_h rr;
}