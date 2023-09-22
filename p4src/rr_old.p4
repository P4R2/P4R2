#include <core.p4>
#include <tna.p4>

typedef bit<48> mac_addr_t;
typedef bit<32> ipv4_addr_t;
typedef bit<16> ether_type_t;
const ether_type_t ETHERTYPE_IPV4 = 16w0x0800;


typedef bit<8> ip_protocol_t;
const ip_protocol_t IP_PROTOCOLS_TCP = 6;
const ip_protocol_t IP_PROTOCOLS_UDP = 17;


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
    bit<3> flags;
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
    bit<8> flags;
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

struct header_t {
    ethernet_h ethernet;
    ipv4_h ipv4;
    tcp_h tcp;
    udp_h udp;
}

//== Metadata definition

struct temp_metadata_t {
    bit<32> temp0;
    bit<32> temp1;
    bit<32> temp2;
    bit<32> temp3;
}

struct key_metadat_t {
    bit<16> filter;
    bit<16> hash_index;
    bit<16> rr0_register_index;
    bit<16> rr1_register_index;
    bit<16> rr2_register_index;
    bit<16> rr3_register_index;
}

struct param_metadata_t {
    bit<1> rr0_param0;
    bit<32> rr0_param1;
    bit<1> rr1_param0;
    bit<32> rr1_param1;
    bit<1> rr2_param0;
    bit<32> rr2_param1;
    bit<1> rr3_param0;
    bit<32> rr3_param1;
}

struct ig_metadata_t {
    temp_metadata_t temp;
    key_metadat_t key;
    param_metadata_t param;
}
struct eg_metadata_t {

}

//== Parser and deparser

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
    out header_t hdr) {
    state start {
        transition parse_ethernet;
    }
    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select (hdr.ethernet.ether_type) {
            ETHERTYPE_IPV4 : parse_ipv4;
            default : reject;
        }
    }
    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            IP_PROTOCOLS_TCP : parse_tcp;
            IP_PROTOCOLS_UDP : parse_udp;
            default : reject;
        }
    }
    state parse_tcp {
        pkt.extract(hdr.tcp);
        transition accept;
    }
    state parse_udp {
        pkt.extract(hdr.udp);
        transition select(hdr.udp.dst_port) {
            default: accept;
        }
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
        layer4_parser.apply(pkt, hdr);
        transition accept;
    }
}

control SwitchIngressDeparser(
        packet_out pkt,
        inout header_t hdr,
        in ig_metadata_t ig_md,
        in ingress_intrinsic_metadata_for_deparser_t ig_intr_dprsr_md) {
    apply {
        pkt.emit(hdr);
    }
}

parser SwitchEgressParser(
        packet_in pkt,
        out header_t hdr,
        out eg_metadata_t ig_md,
        out egress_intrinsic_metadata_t eg_intr_md) {

    EtherIPTCPUDPParser() layer4_parser;
    state start {
        pkt.extract(eg_intr_md);
        layer4_parser.apply(pkt, hdr);
        transition accept;
    }
}

control SwitchEgressDeparser(
        packet_out pkt,
        inout header_t hdr,
        in eg_metadata_t ig_md,
        in egress_intrinsic_metadata_for_deparser_t eg_intr_md_for_dprsr) {
    apply {
        pkt.emit(hdr);
    }
}

//== Control logic
control FS(
        inout header_t hdr,
        inout ig_metadata_t ig_md) {

        action set_filter(bit<16> filterID) {ig_md.key.filter = filterID;}


        table tb_filter_setting {
            key = {
                hdr.ipv4.src : ternary;
                hdr.ipv4.dst : ternary;
                //you can add or delete other field here, but must use ternary match
            }
            actions = {
                set_filter;
                NoAction;
            }
            default_action = NoAction();
        }
        apply {
            tb_filter_setting.apply();
        }
}

control HI(
        inout header_t hdr,
        inout ig_metadata_t ig_md) {

        //you can add or delete other field here
        Hash<bit<16>>(HashAlgorithm_t.CRC32) hash_0;
        Hash<bit<16>>(HashAlgorithm_t.CRC32) hash_1;

        action set_index_hdripv4src() {
            ig_md.key.hash_index = hash_0.get({hdr.ipv4.src});
        }

        action set_index_hdripv4dst() {
            ig_md.key.hash_index = hash_1.get({hdr.ipv4.dst});
        }

        action set_index_manually(bit<16> index) {
            ig_md.key.hash_index = index;
        }

        table tb_hashed_index_setting {
            key = {ig_md.key.filter : exact;}
            actions = {
                set_index_hdripv4src;
                set_index_hdripv4dst;
                set_index_manually;
                NoAction;
            }
            default_action = NoAction();
        }
        apply {
            tb_hashed_index_setting.apply();
        }
}

control AT(
        inout header_t hdr,
        inout ig_metadata_t ig_md) {

        action rr0_shift_1() {ig_md.key.rr0_register_index = ig_md.key.hash_index >> 1;}
        action rr0_shift_2() {ig_md.key.rr0_register_index = ig_md.key.hash_index >> 2;}
        action rr0_shift_3() {ig_md.key.rr0_register_index = ig_md.key.hash_index >> 3;}
        action rr0_add(bit<16> i) {ig_md.key.rr0_register_index = ig_md.key.hash_index + i;}
        action rr1_shift_1() {ig_md.key.rr1_register_index = ig_md.key.hash_index >> 1;}
        action rr1_shift_2() {ig_md.key.rr1_register_index = ig_md.key.hash_index >> 2;}
        action rr1_shift_3() {ig_md.key.rr1_register_index = ig_md.key.hash_index >> 3;}
        action rr1_add(bit<16> i) {ig_md.key.rr1_register_index = ig_md.key.hash_index + i;}
        action rr2_shift_1() {ig_md.key.rr2_register_index = ig_md.key.hash_index >> 1;}
        action rr2_shift_2() {ig_md.key.rr2_register_index = ig_md.key.hash_index >> 2;}
        action rr2_shift_3() {ig_md.key.rr2_register_index = ig_md.key.hash_index >> 3;}
        action rr2_add(bit<16> i) {ig_md.key.rr2_register_index = ig_md.key.hash_index + i;}
        action rr3_shift_1() {ig_md.key.rr3_register_index = ig_md.key.hash_index >> 1;}
        action rr3_shift_2() {ig_md.key.rr3_register_index = ig_md.key.hash_index >> 2;}
        action rr3_shift_3() {ig_md.key.rr3_register_index = ig_md.key.hash_index >> 3;}
        action rr3_add(bit<16> i) {ig_md.key.rr3_register_index = ig_md.key.hash_index + i;}

        table tb_index_shift {
            key = {ig_md.key.filter : exact;}
            actions = {
                NoAction;
                rr0_shift_1;
                rr0_shift_2;
                rr0_shift_3;
                rr1_shift_1;
                rr1_shift_2;
                rr1_shift_3;
                rr2_shift_1;
                rr2_shift_2;
                rr2_shift_3;
                rr3_shift_1;
                rr3_shift_2;
                rr3_shift_3;
            }
            default_action = NoAction();
        }

        table tb_index_add {
            key = {ig_md.key.filter : exact;}
            actions = {
                NoAction;
                rr0_add;
                rr1_add;
                rr2_add;
                rr3_add;
            }
            default_action = NoAction();
        }

        apply {
            tb_index_shift.apply();
            tb_index_add.apply();
        }
}

control PS(
        inout header_t hdr,
        inout ig_metadata_t ig_md) {

        action set_0_0(bit<1> p) {ig_md.param.rr0_param0 = p;}
        action set_0_1(bit<32> p) {ig_md.param.rr0_param1 = p;}
        action set_1_0(bit<1> p) {ig_md.param.rr1_param0 = p;}
        action set_1_1(bit<32> p) {ig_md.param.rr1_param1 = p;}
        action set_2_0(bit<1> p) {ig_md.param.rr2_param0 = p;}
        action set_2_1(bit<32> p) {ig_md.param.rr2_param1 = p;}
        action set_3_0(bit<1> p) {ig_md.param.rr3_param0 = p;}
        action set_3_1(bit<32> p) {ig_md.param.rr3_param1 = p;}

        table tb_parameter_setting0 {
            key = {ig_md.key.filter : exact;}
            actions = {
                set_0_0;
                set_1_0;
                set_2_0;
                set_3_0;
                NoAction;
            }
            default_action = NoAction();
        }

        table tb_parameter_setting1 {
            key = {ig_md.key.filter : exact;}
            actions = {
                set_0_1;
                set_1_1;
                set_2_1;
                set_3_1;
                NoAction;
            }
            default_action = NoAction();
        }
        apply {
            tb_parameter_setting0.apply();
            tb_parameter_setting1.apply();
        }
}

control KS(
        inout header_t hdr,
        inout ig_metadata_t ig_md) {

        action hdripv4src_temp0() {ig_md.temp.temp0 = hdr.ipv4.src;}
        action hdripv4dst_temp0() {ig_md.temp.temp0 = hdr.ipv4.dst;}
        action hdripv4src_temp1() {ig_md.temp.temp1 = hdr.ipv4.src;}
        action hdripv4dst_temp1() {ig_md.temp.temp1 = hdr.ipv4.dst;}
        action hdripv4src_temp2() {ig_md.temp.temp2 = hdr.ipv4.src;}
        action hdripv4dst_temp2() {ig_md.temp.temp2 = hdr.ipv4.dst;}
        action hdripv4src_temp3() {ig_md.temp.temp3 = hdr.ipv4.src;}
        action hdripv4dst_temp3() {ig_md.temp.temp3 = hdr.ipv4.dst;}

        //you can add other key here

        table tb_key_selection {
            key = {ig_md.key.filter : exact;}
            actions = {
                hdripv4src_temp0;
                hdripv4dst_temp0;
                hdripv4src_temp1;
                hdripv4dst_temp1;
                hdripv4src_temp2;
                hdripv4dst_temp2;
                hdripv4src_temp3;
                hdripv4dst_temp3;
                NoAction;
            }
            default_action = NoAction();
        }
        apply {
            tb_key_selection.apply();
        }
}

control HM(
        inout header_t hdr,
        inout ig_metadata_t ig_md) {

        action hdripv4src_temp0() {hdr.ipv4.src = ig_md.temp.temp0;}
        action hdripv4dst_temp0() {hdr.ipv4.dst = ig_md.temp.temp0;}
        action hdripv4src_temp1() {hdr.ipv4.src = ig_md.temp.temp1;}
        action hdripv4dst_temp1() {hdr.ipv4.dst = ig_md.temp.temp1;}
        action hdripv4src_temp2() {hdr.ipv4.src = ig_md.temp.temp2;}
        action hdripv4dst_temp2() {hdr.ipv4.dst = ig_md.temp.temp2;}
        action hdripv4src_temp3() {hdr.ipv4.src = ig_md.temp.temp3;}
        action hdripv4dst_temp3() {hdr.ipv4.dst = ig_md.temp.temp3;}


        table tb_header_modifier {
            key = {ig_md.key.filter : exact;}
            actions = {

                hdripv4src_temp0;
                hdripv4dst_temp0;
                hdripv4src_temp1;
                hdripv4dst_temp1;
                hdripv4src_temp2;
                hdripv4dst_temp2;
                hdripv4src_temp3;
                hdripv4dst_temp3;

                NoAction;
            }
            default_action = NoAction();
        }
        apply {
            tb_header_modifier.apply();
        }
}

control RR(
        inout header_t hdr,
        inout ig_metadata_t ig_md) {


        Register<bit<32>, _>(65536) rr0_register;
        RegisterAction<bit<32>, _, bit<32>>(rr0_register) rr0_op_add_del = {
            void apply(inout bit<32> value, out bit<32> result) {
                if ( ig_md.param.rr0_param0 == 0) {
                    value = value + ig_md.param.rr0_param1;
                }
                else {
                    value = value - ig_md.param.rr0_param1;
                }
                result = value;
            }
        };

        RegisterAction<bit<32>, _, bit<32>>(rr0_register) rr0_op_and_or = {
            void apply(inout bit<32> value, out bit<32> result) {
                if ( ig_md.param.rr0_param0 == 0) {
                    value = value & ig_md.param.rr0_param1;
                }
                else {
                    value = value | ig_md.param.rr0_param1;
                }
                result = value;
            }
        };

        RegisterAction<bit<32>, _, bit<32>>(rr0_register) rr0_op_read_write = {
            void apply(inout bit<32> value, out bit<32> result) {
                if ( ig_md.param.rr0_param0 == 1) {
                    value = ig_md.param.rr0_param1;
                }
                result = value;
            }
        };

        action add_0_1_2() {ig_md.temp.temp0 = ig_md.temp.temp1 + ig_md.temp.temp2;}
        action add_0_1_3() {ig_md.temp.temp0 = ig_md.temp.temp1 + ig_md.temp.temp3;}
        action add_0_2_3() {ig_md.temp.temp0 = ig_md.temp.temp2 + ig_md.temp.temp3;}
        action ass_0_1() {ig_md.temp.temp0 = ~ig_md.temp.temp1;}
        action ass_0_2() {ig_md.temp.temp0 = ~ig_md.temp.temp2;}
        action ass_0_3() {ig_md.temp.temp0 = ~ig_md.temp.temp3;}

        action rr0_reg_op0() {
            rr0_op_add_del.execute(ig_md.key.rr0_register_index);
        }
        action rr0_reg_op1() {
            rr0_op_and_or.execute(ig_md.key.rr0_register_index);
        }
        action rr0_reg_op2() {
            rr0_op_read_write.execute(ig_md.key.rr0_register_index);
        }
        table tb_rr0 {
            key = {ig_md.key.filter : exact;}
            actions = {
                NoAction;
                add_0_1_2
                add_0_1_3
                add_0_2_3
                ass_0_1
                ass_0_2
                ass_0_3
                rr0_reg_op0;
                rr0_reg_op1;
                rr0_reg_op2;
            }
            default_action = NoAction();
        }


        Register<bit<32>, _>(65536) rr1_register;
        RegisterAction<bit<32>, _, bit<32>>(rr1_register) rr1_op_add_del = {
            void apply(inout bit<32> value, out bit<32> result) {
                if ( ig_md.param.rr1_param0 == 0) {
                    value = value + ig_md.param.rr1_param1;
                }
                else {
                    value = value - ig_md.param.rr1_param1;
                }
                result = value;
            }
        };

        RegisterAction<bit<32>, _, bit<32>>(rr1_register) rr1_op_and_or = {
            void apply(inout bit<32> value, out bit<32> result) {
                if ( ig_md.param.rr1_param0 == 0) {
                    value = value & ig_md.param.rr1_param1;
                }
                else {
                    value = value | ig_md.param.rr1_param1;
                }
                result = value;
            }
        };

        RegisterAction<bit<32>, _, bit<32>>(rr1_register) rr1_op_read_write = {
            void apply(inout bit<32> value, out bit<32> result) {
                if ( ig_md.param.rr1_param0 == 1) {
                    value = ig_md.param.rr1_param1;
                }
                result = value;
            }
        };

        action add_1_0_2() {ig_md.temp.temp1 = ig_md.temp.temp0 + ig_md.temp.temp2;}
        action add_1_0_3() {ig_md.temp.temp1 = ig_md.temp.temp0 + ig_md.temp.temp3;}
        action add_1_2_3() {ig_md.temp.temp1 = ig_md.temp.temp2 + ig_md.temp.temp3;}
        action ass_1_0() {ig_md.temp.temp1 = ~ig_md.temp.temp0;}
        action ass_1_2() {ig_md.temp.temp1 = ~ig_md.temp.temp2;}
        action ass_1_3() {ig_md.temp.temp1 = ~ig_md.temp.temp3;}

        action rr1_reg_op0() {
            rr1_op_add_del.execute(ig_md.key.rr1_register_index);
        }
        action rr1_reg_op1() {
            rr1_op_and_or.execute(ig_md.key.rr1_register_index);
        }
        action rr1_reg_op2() {
            rr1_op_read_write.execute(ig_md.key.rr1_register_index);
        }
        table tb_rr1 {
            key = {ig_md.key.filter : exact;}
            actions = {
                NoAction;
                add_1_0_2
                add_1_0_3
                add_1_2_3
                ass_1_0
                ass_1_2
                ass_1_3
                rr1_reg_op0;
                rr1_reg_op1;
                rr1_reg_op2;
            }
            default_action = NoAction();
        }


        Register<bit<32>, _>(65536) rr2_register;
        RegisterAction<bit<32>, _, bit<32>>(rr2_register) rr2_op_add_del = {
            void apply(inout bit<32> value, out bit<32> result) {
                if ( ig_md.param.rr2_param0 == 0) {
                    value = value + ig_md.param.rr2_param1;
                }
                else {
                    value = value - ig_md.param.rr2_param1;
                }
                result = value;
            }
        };

        RegisterAction<bit<32>, _, bit<32>>(rr2_register) rr2_op_and_or = {
            void apply(inout bit<32> value, out bit<32> result) {
                if ( ig_md.param.rr2_param0 == 0) {
                    value = value & ig_md.param.rr2_param1;
                }
                else {
                    value = value | ig_md.param.rr2_param1;
                }
                result = value;
            }
        };

        RegisterAction<bit<32>, _, bit<32>>(rr2_register) rr2_op_read_write = {
            void apply(inout bit<32> value, out bit<32> result) {
                if ( ig_md.param.rr2_param0 == 1) {
                    value = ig_md.param.rr2_param1;
                }
                result = value;
            }
        };

        action add_2_0_1() {ig_md.temp.temp2 = ig_md.temp.temp0 + ig_md.temp.temp1;}
        action add_2_0_3() {ig_md.temp.temp2 = ig_md.temp.temp0 + ig_md.temp.temp3;}
        action add_2_1_3() {ig_md.temp.temp2 = ig_md.temp.temp1 + ig_md.temp.temp3;}
        action ass_2_0() {ig_md.temp.temp2 = ~ig_md.temp.temp0;}
        action ass_2_1() {ig_md.temp.temp2 = ~ig_md.temp.temp1;}
        action ass_2_3() {ig_md.temp.temp2 = ~ig_md.temp.temp3;}

        action rr2_reg_op0() {
            rr2_op_add_del.execute(ig_md.key.rr2_register_index);
        }
        action rr2_reg_op1() {
            rr2_op_and_or.execute(ig_md.key.rr2_register_index);
        }
        action rr2_reg_op2() {
            rr2_op_read_write.execute(ig_md.key.rr2_register_index);
        }
        table tb_rr2 {
            key = {ig_md.key.filter : exact;}
            actions = {
                NoAction;
                add_2_0_1
                add_2_0_3
                add_2_1_3
                ass_2_0
                ass_2_1
                ass_2_3
                rr2_reg_op0;
                rr2_reg_op1;
                rr2_reg_op2;
            }
            default_action = NoAction();
        }


        Register<bit<32>, _>(65536) rr3_register;
        RegisterAction<bit<32>, _, bit<32>>(rr3_register) rr3_op_add_del = {
            void apply(inout bit<32> value, out bit<32> result) {
                if ( ig_md.param.rr3_param0 == 0) {
                    value = value + ig_md.param.rr3_param1;
                }
                else {
                    value = value - ig_md.param.rr3_param1;
                }
                result = value;
            }
        };

        RegisterAction<bit<32>, _, bit<32>>(rr3_register) rr3_op_and_or = {
            void apply(inout bit<32> value, out bit<32> result) {
                if ( ig_md.param.rr3_param0 == 0) {
                    value = value & ig_md.param.rr3_param1;
                }
                else {
                    value = value | ig_md.param.rr3_param1;
                }
                result = value;
            }
        };

        RegisterAction<bit<32>, _, bit<32>>(rr3_register) rr3_op_read_write = {
            void apply(inout bit<32> value, out bit<32> result) {
                if ( ig_md.param.rr3_param0 == 1) {
                    value = ig_md.param.rr3_param1;
                }
                result = value;
            }
        };

        action add_3_0_1() {ig_md.temp.temp3 = ig_md.temp.temp0 + ig_md.temp.temp1;}
        action add_3_0_2() {ig_md.temp.temp3 = ig_md.temp.temp0 + ig_md.temp.temp2;}
        action add_3_1_2() {ig_md.temp.temp3 = ig_md.temp.temp1 + ig_md.temp.temp2;}
        action ass_3_0() {ig_md.temp.temp3 = ~ig_md.temp.temp0;}
        action ass_3_1() {ig_md.temp.temp3 = ~ig_md.temp.temp1;}
        action ass_3_2() {ig_md.temp.temp3 = ~ig_md.temp.temp2;}

        action rr3_reg_op0() {
            rr3_op_add_del.execute(ig_md.key.rr3_register_index);
        }
        action rr3_reg_op1() {
            rr3_op_and_or.execute(ig_md.key.rr3_register_index);
        }
        action rr3_reg_op2() {
            rr3_op_read_write.execute(ig_md.key.rr3_register_index);
        }
        table tb_rr3 {
            key = {ig_md.key.filter : exact;}
            actions = {
                NoAction;
                add_3_0_1
                add_3_0_2
                add_3_1_2
                ass_3_0
                ass_3_1
                ass_3_2
                rr3_reg_op0;
                rr3_reg_op1;
                rr3_reg_op2;
            }
            default_action = NoAction();
        }


        apply {
            tb_rr0.apply();
            tb_rr1.apply();
            tb_rr2.apply();
            tb_rr3.apply();
        }

}


control SwitchIngress(
        inout header_t hdr,
        inout ig_metadata_t ig_md,
        in ingress_intrinsic_metadata_t ig_intr_md,
        in ingress_intrinsic_metadata_from_parser_t ig_intr_prsr_md,
        inout ingress_intrinsic_metadata_for_deparser_t ig_intr_dprsr_md,
        inout ingress_intrinsic_metadata_for_tm_t ig_intr_tm_md) {


        FS() fs0;
        HI() hi0;
        AT() at0;
        PS() ps0;
        KS() ks0;
        KS() ks1;
        HM() hm0;
        HM() hm1;
        RR() rr;
        apply {
            fs0.apply(hdr, ig_md);
            hi0.apply(hdr, ig_md);
            at0.apply(hdr, ig_md);
            ps0.apply(hdr, ig_md);
            ks0.apply(hdr, ig_md);
            ks1.apply(hdr, ig_md);
            hm0.apply(hdr, ig_md);
            hm1.apply(hdr, ig_md);
        }
}

control SwitchEgress(
        inout header_t hdr,
        inout eg_metadata_t ig_md,
        in egress_intrinsic_metadata_t eg_intr_md,
        in egress_intrinsic_metadata_from_parser_t eg_intr_md_from_prsr,
        inout egress_intrinsic_metadata_for_deparser_t ig_intr_dprs_md,
        inout egress_intrinsic_metadata_for_output_port_t eg_intr_oport_md) {
        apply {

        }

}

Pipeline(SwitchIngressParser(),
         SwitchIngress(),
         SwitchIngressDeparser(),
         SwitchEgressParser(),
         SwitchEgress(),
         SwitchEgressDeparser()
         ) pipe;

Switch(pipe) main;
