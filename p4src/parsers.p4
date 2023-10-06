#include "metadata.p4"
#include "headers.p4"

typedef bit<16> ether_type_t;
const ether_type_t ETHERTYPE_IPV4 = 16w0x0800;
const ether_type_t ETHERTYPE_TUNNEL = 16w0x1111;
const ether_type_t ETHERTYPE_CACL = 16w0x2222;


typedef bit<8> ip_protocol_t;
const ip_protocol_t IP_PROTOCOLS_TCP = 6;
const ip_protocol_t IP_PROTOCOLS_UDP = 17;


parser TofinoIngressParser(
        packet_in pkt,
        inout ig_metadata_t ig_md,
        out ingress_intrinsic_metadata_t ig_intr_md) {
    state start {
        pkt.extract(ig_intr_md);
        transition select(ig_intr_md.resubmit_flag) {
            1 : parse_resubmit;
            0 : parse_port_metadata;
        }
    }

    state parse_resubmit {
        // Parse resubmitted packet here.
        pkt.advance(64);
        transition accept;
    }

    state parse_port_metadata {
        pkt.advance(64);  //tofino 1 port metadata size
        transition accept;
    }
}

parser EtherIPTCPUDPParser(
    packet_in pkt,
    inout ig_metadata_t ig_md,
    out header_t hdr) {
    state start {
        ig_md.key.bitmap = 0;
        transition parse_ethernet;
    }
    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        ig_md.key.bitmap = ig_md.key.bitmap | 0x80;
        transition select (hdr.ethernet.ether_type) {
            ETHERTYPE_IPV4 : parse_ipv4;
            ETHERTYPE_TUNNEL : parse_tunnel;
            ETHERTYPE_CACL : parse_cacl;
            default : reject;
        }
    }
    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        ig_md.key.bitmap = ig_md.key.bitmap | 0x40;
        transition select(hdr.ipv4.protocol) {
            IP_PROTOCOLS_TCP : parse_tcp;
            IP_PROTOCOLS_UDP : parse_udp;
            default : reject;
        }
    }
    state parse_tunnel {
        ig_md.key.bitmap = ig_md.key.bitmap | 0x20;
        pkt.extract(hdr.tunnel);
        transition accept;
    }
    state parse_cacl {
        ig_md.key.bitmap = ig_md.key.bitmap | 0x10;
        pkt.extract(hdr.cacl);
        transition accept;
    }
    state parse_tcp {
        ig_md.key.bitmap = ig_md.key.bitmap | 0x08;
        pkt.extract(hdr.tcp);
        transition parse_rr_pre;
    }
    state parse_udp {
        pkt.extract(hdr.udp);
        ig_md.key.bitmap = ig_md.key.bitmap | 0x04;
        transition select(hdr.udp.dst_port) {
            8888 : parse_nc;
            default: parse_rr_pre;
        }
    }
    state parse_nc {
        pkt.extract(hdr.nc);
        ig_md.key.bitmap = ig_md.key.bitmap | 0x02;
        transition parse_rr_pre;
    }
    state parse_rr_pre {
        transition select(hdr.ipv4.rec) {
            1 : parse_rr;
            default: accept;
        }
    }
    state parse_rr {
        ig_md.key.bitmap = ig_md.key.bitmap | 0x01;
        pkt.extract(hdr.rr);
        transition accept;
    }
}

parser SwitchIngressParser(
        packet_in pkt,
        out header_t hdr,
        out ig_metadata_t ig_md,
        out ingress_intrinsic_metadata_t ig_intr_md) {

    TofinoIngressParser() tofino_parser;
    EtherIPTCPUDPParser() layer4_parser;

    state start {
        tofino_parser.apply(pkt, ig_md, ig_intr_md);
        layer4_parser.apply(pkt, ig_md, hdr);
        transition accept;
    }
}

control SwitchIngressDeparser(
        packet_out pkt,
        inout header_t hdr,
        in ig_metadata_t ig_md,
        in ingress_intrinsic_metadata_for_deparser_t ig_intr_dprsr_md) {
    apply {
        pkt.emit(hdr.ethernet);
        pkt.emit(hdr.ipv4);
        pkt.emit(hdr.tunnel);
        pkt.emit(hdr.cacl);
        pkt.emit(hdr.tcp);
        pkt.emit(hdr.udp);
        pkt.emit(hdr.rr);
    }
}

parser SwitchEgressParser(
        packet_in pkt,
        out header_t hdr,
        out eg_metadata_t eg_md,
        out egress_intrinsic_metadata_t eg_intr_md) {

    state start {
        pkt.extract(eg_intr_md);
        transition accept;
    }
}

control SwitchEgressDeparser(
        packet_out pkt,
        inout header_t hdr,
        in eg_metadata_t eg_md,
        in egress_intrinsic_metadata_for_deparser_t eg_intr_md_for_dprsr) {
    apply {
        pkt.emit(hdr);
    }
}