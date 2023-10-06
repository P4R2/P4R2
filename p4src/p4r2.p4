#include <core.p4>
#include <tna.p4>
#include "parsers.p4"
//== Control logic
control FS(
        inout header_t hdr,
        inout ig_metadata_t ig_md,
        in ingress_intrinsic_metadata_t ig_intr_md) {

        action set_filter0(bit<16> filterID) {ig_md.key.filter0 = filterID;}
        action set_filter1(bit<16> filterID) {ig_md.key.filter1 = filterID;}
        action set_filter2(bit<16> filterID) {ig_md.key.filter2 = filterID;}
        action set_filter3(bit<16> filterID) {ig_md.key.filter3 = filterID;}
        action set_filter4(bit<16> filterID) {ig_md.key.filter4 = filterID;}
        action set_filter5(bit<16> filterID) {ig_md.key.filter5 = filterID;}
        action set_filter6(bit<16> filterID) {ig_md.key.filter6 = filterID;}

        //parsing logic: ethernet -> ipv4 -> tcp 
        table tb_filter_setting0 {
            key = {
                ig_intr_md.ingress_port : ternary;
                hdr.ipv4.dst : ternary;
                //hdr.tunnel.dst_id : ternary;
                //hdr.cacl.op : ternary;
                hdr.tcp.syn : ternary;
                //hdr.nc.key : ternary;
                //hdr.nc.op : ternary;
                //hdr.rr.info: ternary;
                //hdr.rr.time: exact;
                ig_md.key.bitmap : exact;
                //you can add or delete other field here
            }
            actions = {
                set_filter0;
                NoAction;
            }
            default_action = NoAction();
        }

        table tb_filter_setting1 {
            key = {
                ig_intr_md.ingress_port : ternary;
                hdr.ipv4.dst : ternary;
                //hdr.tunnel.dst_id : ternary;
                //hdr.cacl.op : ternary;
                hdr.tcp.syn : ternary;
                //hdr.nc.key : ternary;
                //hdr.nc.op : ternary;
                hdr.rr.info: ternary;
                hdr.rr.time: exact;
                ig_md.key.bitmap : exact;
                //you can add or delete other field here
            }
            actions = {
                set_filter1;
                NoAction;
            }
            default_action = NoAction();
        }

        table tb_filter_setting2 {
            key = {
                ig_intr_md.ingress_port : ternary;
                hdr.ipv4.dst : ternary;
                //hdr.tunnel.dst_id : ternary;
                //hdr.cacl.op : ternary;
                //hdr.tcp.syn : ternary;
                //hdr.nc.key : ternary;
                //hdr.nc.op : ternary;
                //hdr.rr.info: ternary;
                //hdr.rr.time: exact;
                ig_md.key.bitmap : exact;
                //you can add or delete other field here
            }
            actions = {
                set_filter2;
                NoAction;
            }
            default_action = NoAction();
        }

        table tb_filter_setting3 {
            key = {
                ig_intr_md.ingress_port : ternary;
                hdr.ipv4.dst : ternary;
                //hdr.tunnel.dst_id : ternary;
                //hdr.cacl.op : ternary;
                //hdr.tcp.syn : ternary;
                //hdr.nc.key : ternary;
                //hdr.nc.op : ternary;
                hdr.rr.info: ternary;
                hdr.rr.time: exact;
                ig_md.key.bitmap : exact;
                //you can add or delete other field here
            }
            actions = {
                set_filter3;
                NoAction;
            }
            default_action = NoAction();
        }

        table tb_filter_setting4 {
            key = {
                ig_intr_md.ingress_port : ternary;
                hdr.ipv4.dst : ternary;
                //hdr.tunnel.dst_id : ternary;
                //hdr.cacl.op : ternary;
                //hdr.tcp.syn : ternary;
                hdr.nc.key : ternary;
                hdr.nc.op : ternary;
                //hdr.rr.info: ternary;
                //hdr.rr.time: exact;
                ig_md.key.bitmap : exact;
                //you can add or delete other field here
            }
            actions = {
                set_filter4;
                NoAction;
            }
            default_action = NoAction();
        }

        table tb_filter_setting5 {
            key = {
                ig_intr_md.ingress_port : ternary;
                //hdr.ipv4.dst : ternary;
                hdr.tunnel.dst_id : ternary;
                //hdr.cacl.op : ternary;
                //hdr.tcp.syn : ternary;
                //hdr.nc.key : ternary;
                //hdr.nc.op : ternary;
                //hdr.rr.info: ternary;
                //hdr.rr.time: exact;
                ig_md.key.bitmap : exact;
                //you can add or delete other field here
            }
            actions = {
                set_filter5;
                NoAction;
            }
            default_action = NoAction();
        }

        table tb_filter_setting6 {
            key = {
                ig_intr_md.ingress_port : ternary;
                //hdr.ipv4.dst : ternary;
                //hdr.tunnel.dst_id : ternary;
                hdr.cacl.op : ternary;
                //hdr.tcp.syn : ternary;
                //hdr.nc.key : ternary;
                //hdr.nc.op : ternary;
                //hdr.rr.info: ternary;
                //hdr.rr.time: exact;
                ig_md.key.bitmap : exact;
                //you can add or delete other field here
            }
            actions = {
                set_filter6;
                NoAction;
            }
            default_action = NoAction();
        }

        apply {
            tb_filter_setting0.apply();
            tb_filter_setting1.apply();
            tb_filter_setting2.apply();
            tb_filter_setting3.apply();
            tb_filter_setting4.apply();
            tb_filter_setting5.apply();
            tb_filter_setting6.apply();
        }
}

control HI(
        inout header_t hdr,
        inout ig_metadata_t ig_md) {

        //you can add or delete other field here
        Hash<bit<16>>(HashAlgorithm_t.CRC32) hash_0_0;
        Hash<bit<16>>(HashAlgorithm_t.CRC32) hash_0_1;

        //action set_index0_hdripv4src() {
        //    ig_md.key.hash_index0 = hash_0.get({hdr.ipv4.src});
        //}

        action set_index0_5_tuple() {
            ig_md.key.hash_index0 = hash_0_0.get({hdr.ipv4.src, hdr.ipv4.dst, hdr.tcp.src_port, hdr.tcp.dst_port, hdr.ipv4.protocol});
        }

        action set_index0_5_tuple_swap() {
            ig_md.key.hash_index0 = hash_0_1.get({hdr.ipv4.dst, hdr.ipv4.src, hdr.tcp.dst_port, hdr.tcp.src_port, hdr.ipv4.protocol});
        }

        action set_index0_manually(bit<16> index) {
            ig_md.key.hash_index0 = index;
        }

        table tb_hashed_index0_setting {
            key = {
                ig_md.key.filter0 : exact;
                ig_md.key.filter1 : exact;
                ig_md.key.filter2 : exact;
                ig_md.key.filter3 : exact;
                ig_md.key.filter4 : exact;
                ig_md.key.filter5 : exact;
                ig_md.key.filter6 : exact;
            }
            actions = {
                //set_index0_hdripv4src;
                set_index0_manually;
                set_index0_5_tuple;
                set_index0_5_tuple_swap;
                NoAction;
            }
            default_action = NoAction();
        }

        Hash<bit<16>>(HashAlgorithm_t.CRC32) hash_1;

        action set_index1_hdripv4src() {
            ig_md.key.hash_index1 = hash_1.get({hdr.ipv4.src});
        }

        action set_index1_manually(bit<16> index) {
            ig_md.key.hash_index1 = index;
        }

        table tb_hashed_index1_setting {
            key = {
                ig_md.key.filter0 : exact;
                ig_md.key.filter1 : exact;
                ig_md.key.filter2 : exact;
                ig_md.key.filter3 : exact;
                ig_md.key.filter4 : exact;
                ig_md.key.filter5 : exact;
                ig_md.key.filter6 : exact;
            }
            actions = {
                set_index1_hdripv4src;
                set_index1_manually;
                NoAction;
            }
            default_action = NoAction();
        }

        Hash<bit<16>>(HashAlgorithm_t.CRC32) hash_2;

        action set_index2_hdripv4src() {
            ig_md.key.hash_index2 = hash_2.get({hdr.ipv4.src});
        }

        action set_index2_manually(bit<16> index) {
            ig_md.key.hash_index2 = index;
        }

        table tb_hashed_index2_setting {
            key = {
                ig_md.key.filter0 : exact;
                ig_md.key.filter1 : exact;
                ig_md.key.filter2 : exact;
                ig_md.key.filter3 : exact;
                ig_md.key.filter4 : exact;
                ig_md.key.filter5 : exact;
                ig_md.key.filter6 : exact;
            }
            actions = {
                set_index2_hdripv4src;
                set_index2_manually;
                NoAction;
            }
            default_action = NoAction();
        }
        apply {
            tb_hashed_index0_setting.apply();
            tb_hashed_index1_setting.apply();
            tb_hashed_index2_setting.apply();
        }
}

control AT(
        inout header_t hdr,
        inout ig_metadata_t ig_md) {

        action rr1_shift_1() {ig_md.key.hash_index2 = ig_md.key.hash_index2 >> 1;}
        action rr1_shift_2() {ig_md.key.hash_index2 = ig_md.key.hash_index2 >> 2;}
        action rr1_shift_3() {ig_md.key.hash_index2 = ig_md.key.hash_index2 >> 3;}
        action rr1_add(bit<16> i) {ig_md.key.rr1_register_index = ig_md.key.hash_index2 + i;}
        action rr2_shift_1() {ig_md.key.hash_index1  = ig_md.key.hash_index1 >> 1;}
        action rr2_shift_2() {ig_md.key.hash_index1  = ig_md.key.hash_index1 >> 2;}
        action rr2_shift_3() {ig_md.key.hash_index1  = ig_md.key.hash_index1 >> 3;}
        action rr2_add(bit<16> i) {ig_md.key.rr2_register_index = ig_md.key.hash_index1 + i;}
        action rr3_shift_1() {ig_md.key.hash_index0 = ig_md.key.hash_index0 >> 1;}
        action rr3_shift_2() {ig_md.key.hash_index0 = ig_md.key.hash_index0 >> 2;}
        action rr3_shift_3() {ig_md.key.hash_index0 = ig_md.key.hash_index0 >> 3;}
        action rr3_add(bit<16> i) {ig_md.key.rr3_register_index = ig_md.key.hash_index0 + i;}

        table tb_rr1_index_shift {
            key = {
                ig_md.key.filter0 : exact;
                ig_md.key.filter1 : exact;
                ig_md.key.filter2 : exact;
                ig_md.key.filter3 : exact;
                ig_md.key.filter4 : exact;
                ig_md.key.filter5 : exact;
                ig_md.key.filter6 : exact;
            }
            actions = {
                NoAction;
                rr1_shift_1;
                rr1_shift_2;
                rr1_shift_3;
            }
            default_action = NoAction();
        }

        table tb_rr1_index_add {
            key = {
                ig_md.key.filter0 : exact;
                ig_md.key.filter1 : exact;
                ig_md.key.filter2 : exact;
                ig_md.key.filter3 : exact;
                ig_md.key.filter4 : exact;
                ig_md.key.filter5 : exact;
                ig_md.key.filter6 : exact;
            }
            actions = {
                NoAction;
                rr1_add;
            }
            default_action = NoAction();
        }

        table tb_rr2_index_shift {
            key = {
                ig_md.key.filter0 : exact;
                ig_md.key.filter1 : exact;
                ig_md.key.filter2 : exact;
                ig_md.key.filter3 : exact;
                ig_md.key.filter4 : exact;
                ig_md.key.filter5 : exact;
                ig_md.key.filter6 : exact;
            }
            actions = {
                NoAction;
                rr2_shift_1;
                rr2_shift_2;
                rr2_shift_3;
            }
            default_action = NoAction();
        }

        table tb_rr2_index_add {
            key = {
                ig_md.key.filter0 : exact;
                ig_md.key.filter1 : exact;
                ig_md.key.filter2 : exact;
                ig_md.key.filter3 : exact;
                ig_md.key.filter4 : exact;
                ig_md.key.filter5 : exact;
                ig_md.key.filter6 : exact;
            }
            actions = {
                NoAction;
                rr2_add;
            }
            default_action = NoAction();
        }

        table tb_rr3_index_shift {
            key = {
                ig_md.key.filter0 : exact;
                ig_md.key.filter1 : exact;
                ig_md.key.filter2 : exact;
                ig_md.key.filter3 : exact;
                ig_md.key.filter4 : exact;
                ig_md.key.filter5 : exact;
                ig_md.key.filter6 : exact;
            }
            actions = {
                NoAction;
                rr3_shift_1;
                rr3_shift_2;
                rr3_shift_3;
            }
            default_action = NoAction();
        }

        table tb_rr3_index_add {
            key = {
                ig_md.key.filter0 : exact;
                ig_md.key.filter1 : exact;
                ig_md.key.filter2 : exact;
                ig_md.key.filter3 : exact;
                ig_md.key.filter4 : exact;
                ig_md.key.filter5 : exact;
                ig_md.key.filter6 : exact;
            }
            actions = {
                NoAction;
                rr3_add;
            }
            default_action = NoAction();
        }
        apply {
            tb_rr1_index_shift.apply();
            tb_rr1_index_add.apply();
            tb_rr2_index_shift.apply();
            tb_rr2_index_add.apply();
            tb_rr3_index_shift.apply();
            tb_rr3_index_add.apply();
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
        action set_1_hdripv4total_len() {ig_md.param.rr1_param1 = (bit<32>)hdr.ipv4.total_len;}
        action set_2_hdripv4total_len() {ig_md.param.rr2_param1 = (bit<32>)hdr.ipv4.total_len;}
        action set_3_hdripv4total_len() {ig_md.param.rr3_param1 = (bit<32>)hdr.ipv4.total_len;}
        action set_3_hdrncvalue() {ig_md.param.rr3_param1 = hdr.nc.value;}
        action set_3_hdrrrinfo() {ig_md.param.rr3_param1 = hdr.rr.info;}

        table tb_rr0_parameter_setting0 {
            key = {
                ig_md.key.filter0 : exact;
                ig_md.key.filter1 : exact;
                ig_md.key.filter2 : exact;
                ig_md.key.filter3 : exact;
                ig_md.key.filter4 : exact;
                ig_md.key.filter5 : exact;
                ig_md.key.filter6 : exact;
            }
            actions = {
                set_0_0;
                NoAction;
            }
            default_action = NoAction();
        }

        table tb_rr0_parameter_setting1 {
            key = {
                ig_md.key.filter0 : exact;
                ig_md.key.filter1 : exact;
                ig_md.key.filter2 : exact;
                ig_md.key.filter3 : exact;
                ig_md.key.filter4 : exact;
                ig_md.key.filter5 : exact;
                ig_md.key.filter6 : exact;
            }
            actions = {
                set_0_1;
                NoAction;
            }
            default_action = NoAction();
        }

        table tb_rr1_parameter_setting0 {
            key = {
                ig_md.key.filter0 : exact;
                ig_md.key.filter1 : exact;
                ig_md.key.filter2 : exact;
                ig_md.key.filter3 : exact;
                ig_md.key.filter4 : exact;
                ig_md.key.filter5 : exact;
                ig_md.key.filter6 : exact;
            }
            actions = {
                set_1_0;
                NoAction;
            }
            default_action = NoAction();
        }

        table tb_rr1_parameter_setting1 {
            key = {
                ig_md.key.filter0 : exact;
                ig_md.key.filter1 : exact;
                ig_md.key.filter2 : exact;
                ig_md.key.filter3 : exact;
                ig_md.key.filter4 : exact;
                ig_md.key.filter5 : exact;
                ig_md.key.filter6 : exact;
            }
            actions = {
                set_1_1;
                set_1_hdripv4total_len;
                NoAction;
            }
            default_action = NoAction();
        }

        table tb_rr2_parameter_setting0 {
            key = {
                ig_md.key.filter0 : exact;
                ig_md.key.filter1 : exact;
                ig_md.key.filter2 : exact;
                ig_md.key.filter3 : exact;
                ig_md.key.filter4 : exact;
                ig_md.key.filter5 : exact;
                ig_md.key.filter6 : exact;
            }
            actions = {
                set_2_0;
                NoAction;
            }
            default_action = NoAction();
        }

        table tb_rr2_parameter_setting1 {
            key = {
                ig_md.key.filter0 : exact;
                ig_md.key.filter1 : exact;
                ig_md.key.filter2 : exact;
                ig_md.key.filter3 : exact;
                ig_md.key.filter4 : exact;
                ig_md.key.filter5 : exact;
                ig_md.key.filter6 : exact;
            }
            actions = {
                set_2_1;
                set_2_hdripv4total_len;
                NoAction;
            }
            default_action = NoAction();
        }

        table tb_rr3_parameter_setting0 {
            key = {
                ig_md.key.filter0 : exact;
                ig_md.key.filter1 : exact;
                ig_md.key.filter2 : exact;
                ig_md.key.filter3 : exact;
                ig_md.key.filter4 : exact;
                ig_md.key.filter5 : exact;
                ig_md.key.filter6 : exact;
            }
            actions = {
                set_3_0;
                NoAction;
            }
            default_action = NoAction();
        }

        table tb_rr3_parameter_setting1 {
            key = {
                ig_md.key.filter0 : exact;
                ig_md.key.filter1 : exact;
                ig_md.key.filter2 : exact;
                ig_md.key.filter3 : exact;
                ig_md.key.filter4 : exact;
                ig_md.key.filter5 : exact;
                ig_md.key.filter6 : exact;
            }
            actions = {
                set_3_1;
                set_3_hdripv4total_len;
                set_3_hdrncvalue;
                set_3_hdrrrinfo;
                NoAction;
            }
            default_action = NoAction();
        }

        apply {
            //tb_rr0_parameter_setting0.apply();
            //tb_rr0_parameter_setting1.apply();
            tb_rr1_parameter_setting0.apply();
            tb_rr1_parameter_setting1.apply();
            tb_rr2_parameter_setting0.apply();
            tb_rr2_parameter_setting1.apply();
            tb_rr3_parameter_setting0.apply();
            tb_rr3_parameter_setting1.apply();
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
        action hdrrrinfo_temp0() {ig_md.temp.temp0 = hdr.rr.info;}
        action hdrcaclopA_temp1() {ig_md.temp.temp1 = hdr.cacl.opA;}
        action hdrcaclopB_temp2() {ig_md.temp.temp2 = hdr.cacl.opB;}
        action ig_mdkeyhash_index0_temp0() {ig_md.temp.temp0 = (bit<32>)ig_md.key.hash_index0;}

        //you can add other key here

        table tb_key_selection {
            key = {
                ig_md.key.filter0 : exact;
                ig_md.key.filter1 : exact;
                ig_md.key.filter2 : exact;
                ig_md.key.filter3 : exact;
                ig_md.key.filter4 : exact;
                ig_md.key.filter5 : exact;
                ig_md.key.filter6 : exact;
            }
            actions = {
                hdripv4src_temp0;
                hdripv4dst_temp0;
                hdripv4src_temp1;
                hdripv4dst_temp1;
                hdripv4src_temp2;
                hdripv4dst_temp2;
                hdripv4src_temp3;
                hdripv4dst_temp3;
                hdrcaclopA_temp1;
                hdrcaclopB_temp2;
                ig_mdkeyhash_index0_temp0;
                //hdrrrinfo_temp0;
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
        inout ig_metadata_t ig_md,
        inout ingress_intrinsic_metadata_for_deparser_t ig_intr_dprsr_md,
        inout ingress_intrinsic_metadata_for_tm_t ig_intr_tm_md) {

        action hdripv4src_temp0() {hdr.ipv4.src = ig_md.temp.temp0;}
        action hdripv4dst_temp0() {hdr.ipv4.dst = ig_md.temp.temp0;}
        action hdripv4src_temp1() {hdr.ipv4.src = ig_md.temp.temp1;}
        action hdripv4dst_temp1() {hdr.ipv4.dst = ig_md.temp.temp1;}
        action hdripv4src_temp2() {hdr.ipv4.src = ig_md.temp.temp2;}
        action hdripv4dst_temp2() {hdr.ipv4.dst = ig_md.temp.temp2;}
        action hdripv4src_temp3() {hdr.ipv4.src = ig_md.temp.temp3;}
        action hdripv4dst_temp3() {hdr.ipv4.dst = ig_md.temp.temp3;}
        action hdrrrinfo_temp0() {hdr.rr.info = ig_md.param.rr3_param1;}
        action ig_intr_dprsr_mddrop_ctl_temp0() {ig_intr_dprsr_md.drop_ctl = (bit<3>)ig_md.temp.temp0;}
        action ig_intr_tm_mducast_egress_port_temp0() {ig_intr_tm_md.ucast_egress_port = (bit<9>)ig_md.temp.temp0;}
        action hdrcaclres_temp0() {hdr.cacl.res = ig_md.temp.temp0;}
        action hdrrrinfo_ig_mdparamrr3_param1() {hdr.rr.info = ig_md.param.rr3_param1;}
        action hdrncvalue_ig_mdparamrr3_param1() {hdr.nc.value = ig_md.param.rr3_param1;}


        table tb_header_modifier {
            key = {
                ig_md.key.filter0 : exact;
                ig_md.key.filter1 : exact;
                ig_md.key.filter2 : exact;
                ig_md.key.filter3 : exact;
                ig_md.key.filter4 : exact;
                ig_md.key.filter5 : exact;
                ig_md.key.filter6 : exact;
            }
            actions = {

                hdripv4src_temp0;
                hdripv4dst_temp0;
                hdripv4src_temp1;
                hdripv4dst_temp1;
                hdripv4src_temp2;
                hdripv4dst_temp2;
                hdripv4src_temp3;
                hdripv4dst_temp3;
                ig_intr_dprsr_mddrop_ctl_temp0;
                ig_intr_tm_mducast_egress_port_temp0;
                hdrcaclres_temp0;
                hdrrrinfo_ig_mdparamrr3_param1;
                hdrncvalue_ig_mdparamrr3_param1;
                hdrrrinfo_temp0;
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
        RegisterAction<bit<32>, _, bit<32>>(rr0_register) rr0_op_add_sub = {
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
        action ass_0_1() {ig_md.temp.temp0 = ig_md.temp.temp1;}
        action ass_0_2() {ig_md.temp.temp0 = ig_md.temp.temp2;}
        action ass_0_3() {ig_md.temp.temp0 = ig_md.temp.temp3;}
        action add_0_0_i(bit<32> i) {ig_md.temp.temp0 = ig_md.temp.temp0 + i;}
        // action and_0_1_i(bit<32> i) {ig_md.temp.temp0 = ig_md.temp.temp1 & i;}
        // action or_0_1_i(bit<32> i) {ig_md.temp.temp0 = ig_md.temp.temp1 | i;}
        // action xor_0_1_i(bit<32> i) {ig_md.temp.temp0 = ig_md.temp.temp1 ^ i;}
        // action not_0_1(bit<32> i) {ig_md.temp.temp0 = ~ig_md.temp.temp1;}

        action sub_0_1_2() {ig_md.temp.temp0 = ig_md.temp.temp1 - ig_md.temp.temp2;}
        // action mul_0_1_2() {ig_md.temp.temp0 = ig_md.temp.temp1 * ig_md.temp.temp2;}
        action and_0_1_2() {ig_md.temp.temp0 = ig_md.temp.temp1 & ig_md.temp.temp2;}
        action or_0_1_2() {ig_md.temp.temp0 = ig_md.temp.temp1 | ig_md.temp.temp2;}
        action xor_0_1_2() {ig_md.temp.temp0 = ig_md.temp.temp1 ^ ig_md.temp.temp2;}
        // action lshift_0_1_2() {ig_md.temp.temp0 = ig_md.temp.temp1 << ig_md.temp.temp2;}
        // action rshift_0_1_2() {ig_md.temp.temp0 = ig_md.temp.temp1 >> ig_md.temp.temp2;} 

        action rr0_reg_op0() {
            rr0_op_add_sub.execute(ig_md.key.rr0_register_index);
        }
        action rr0_reg_op1() {
            rr0_op_and_or.execute(ig_md.key.rr0_register_index);
        }
        action rr0_reg_op2() {
            ig_md.param.rr0_param1 = rr0_op_read_write.execute(ig_md.key.rr0_register_index);
        }
        table tb_rr0 {
            key = {
                ig_md.key.filter0 : exact;
                ig_md.key.filter1 : exact;
                ig_md.key.filter2 : exact;
                ig_md.key.filter3 : exact;
                ig_md.key.filter4 : exact;
                ig_md.key.filter5 : exact;
                ig_md.key.filter6 : exact;
            }
            actions = {
                NoAction;
                add_0_1_2;
                add_0_1_3;
                add_0_2_3;
                ass_0_1;
                ass_0_2;
                ass_0_3;
                add_0_0_i;
                sub_0_1_2;
                and_0_1_2;
                or_0_1_2;
                xor_0_1_2;
                //and_0_1_i;
                //or_0_1_i;
                //xor_0_1_i;
                //not_0_1;
                //lshift_0_1_i;
                //rshift_0_1_i;
            }
            default_action = NoAction();
        }
        table tb_rr0_reg {
            key = {
                ig_md.key.filter0 : exact;
                ig_md.key.filter1 : exact;
                ig_md.key.filter2 : exact;
                ig_md.key.filter3 : exact;
                ig_md.key.filter4 : exact;
                ig_md.key.filter5 : exact;
                ig_md.key.filter6 : exact;
            }
            actions = {
                NoAction;
                rr0_reg_op0;
                rr0_reg_op1;
                rr0_reg_op2;
            }
            default_action = NoAction();
        }


        Register<bit<32>, _>(65536) rr1_register;
        RegisterAction<bit<32>, _, bit<32>>(rr1_register) rr1_op_add_sub = {
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

        RegisterAction<bit<32>, _, bit<32>>(rr1_register) rr1_op_max = {
            void apply(inout bit<32> value, out bit<32> result) {
                if ( ig_md.param.rr1_param1 > value) {
                    value = ig_md.param.rr1_param1;
                }
                result = value;
            }
        };

        action add_1_0_2() {ig_md.temp.temp1 = ig_md.temp.temp0 + ig_md.temp.temp2;}
        action add_1_0_3() {ig_md.temp.temp1 = ig_md.temp.temp0 + ig_md.temp.temp3;}
        action add_1_2_3() {ig_md.temp.temp1 = ig_md.temp.temp2 + ig_md.temp.temp3;}
        action ass_1_0() {ig_md.temp.temp1 = ig_md.temp.temp0;}
        action ass_1_2() {ig_md.temp.temp1 = ig_md.temp.temp2;}
        action ass_1_3() {ig_md.temp.temp1 = ig_md.temp.temp3;}

        action rr1_reg_op0() {
            rr1_op_add_sub.execute(ig_md.key.rr1_register_index);
        }
        action rr1_reg_op1() {
            rr1_op_and_or.execute(ig_md.key.rr1_register_index);
        }
        action rr1_reg_op2() {
            ig_md.param.rr1_param1 = rr1_op_read_write.execute(ig_md.key.rr1_register_index);
        }
        action rr1_reg_op3() {
            rr1_op_max.execute(ig_md.key.rr1_register_index);
        }
        table tb_rr1 {
            key = {
                ig_md.key.filter0 : exact;
                ig_md.key.filter1 : exact;
                ig_md.key.filter2 : exact;
                ig_md.key.filter3 : exact;
                ig_md.key.filter4 : exact;
                ig_md.key.filter5 : exact;
                ig_md.key.filter6 : exact;
            }
            actions = {
                NoAction;
                add_1_0_2;
                add_1_0_3;
                add_1_2_3;
                ass_1_0;
                ass_1_2;
                ass_1_3;
            }
            default_action = NoAction();
        }
        table tb_rr1_reg {
            key = {
                ig_md.key.filter0 : exact;
                ig_md.key.filter1 : exact;
                ig_md.key.filter2 : exact;
                ig_md.key.filter3 : exact;
                ig_md.key.filter4 : exact;
                ig_md.key.filter5 : exact;
                ig_md.key.filter6 : exact;
            }
            actions = {
                NoAction;
                rr1_reg_op0;
                rr1_reg_op1;
                rr1_reg_op2;
                rr1_reg_op3;
            }
            default_action = NoAction();
        }


        Register<bit<32>, _>(65536) rr2_register;
        RegisterAction<bit<32>, _, bit<32>>(rr2_register) rr2_op_add_sub = {
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

        RegisterAction<bit<32>, _, bit<32>>(rr2_register) rr2_op_max = {
            void apply(inout bit<32> value, out bit<32> result) {
                if ( ig_md.param.rr2_param1 > value) {
                    value = ig_md.param.rr2_param1;
                }
                result = value;
            }
        };

        action add_2_0_1() {ig_md.temp.temp2 = ig_md.temp.temp0 + ig_md.temp.temp1;}
        action add_2_0_3() {ig_md.temp.temp2 = ig_md.temp.temp0 + ig_md.temp.temp3;}
        action add_2_1_3() {ig_md.temp.temp2 = ig_md.temp.temp1 + ig_md.temp.temp3;}
        action ass_2_0() {ig_md.temp.temp2 = ig_md.temp.temp0;}
        action ass_2_1() {ig_md.temp.temp2 = ig_md.temp.temp1;}
        action ass_2_3() {ig_md.temp.temp2 = ig_md.temp.temp3;}

        action rr2_reg_op0() {
            rr2_op_add_sub.execute(ig_md.key.rr2_register_index);
        }
        action rr2_reg_op1() {
            rr2_op_and_or.execute(ig_md.key.rr2_register_index);
        }
        action rr2_reg_op2() {
            ig_md.param.rr2_param1 = rr2_op_read_write.execute(ig_md.key.rr2_register_index);
        }
        action rr2_reg_op3() {
            rr2_op_max.execute(ig_md.key.rr2_register_index);
        }
        table tb_rr2 {
            key = {
                ig_md.key.filter0 : exact;
                ig_md.key.filter1 : exact;
                ig_md.key.filter2 : exact;
                ig_md.key.filter3 : exact;
                ig_md.key.filter4 : exact;
                ig_md.key.filter5 : exact;
                ig_md.key.filter6 : exact;
            }
            actions = {
                NoAction;
                add_2_0_1;
                add_2_0_3;
                add_2_1_3;
                ass_2_0;
                ass_2_1;
                ass_2_3;
            }
            default_action = NoAction();
        }
        table tb_rr2_reg {
            key = {
                ig_md.key.filter0 : exact;
                ig_md.key.filter1 : exact;
                ig_md.key.filter2 : exact;
                ig_md.key.filter3 : exact;
                ig_md.key.filter4 : exact;
                ig_md.key.filter5 : exact;
                ig_md.key.filter6 : exact;
            }
            actions = {
                NoAction;
                rr2_reg_op0;
                rr2_reg_op1;
                rr2_reg_op2;
                rr2_reg_op3;
            }
            default_action = NoAction();
        }


        Register<bit<32>, _>(65536) rr3_register;
        RegisterAction<bit<32>, _, bit<32>>(rr3_register) rr3_op_add_sub = {
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

        RegisterAction<bit<32>, _, bit<32>>(rr3_register) rr3_op_max = {
            void apply(inout bit<32> value, out bit<32> result) {
                if ( ig_md.param.rr3_param1 > value) {
                    value = ig_md.param.rr3_param1;
                }
                result = value;
            }
        };

        action add_3_0_1() {ig_md.temp.temp3 = ig_md.temp.temp0 + ig_md.temp.temp1;}
        action add_3_0_2() {ig_md.temp.temp3 = ig_md.temp.temp0 + ig_md.temp.temp2;}
        action add_3_1_2() {ig_md.temp.temp3 = ig_md.temp.temp1 + ig_md.temp.temp2;}
        action ass_3_0() {ig_md.temp.temp3 = ig_md.temp.temp0;}
        action ass_3_1() {ig_md.temp.temp3 = ig_md.temp.temp1;}
        action ass_3_2() {ig_md.temp.temp3 = ig_md.temp.temp2;}

        action rr3_reg_op0() {
            rr3_op_add_sub.execute(ig_md.key.rr3_register_index);
        }
        action rr3_reg_op1() {
            rr3_op_and_or.execute(ig_md.key.rr3_register_index);
        }
        action rr3_reg_op2() {
            ig_md.param.rr3_param1 = rr3_op_read_write.execute(ig_md.key.rr3_register_index);
        }
        action rr3_reg_op3() {
            rr3_op_max.execute(ig_md.key.rr3_register_index);
        }
        table tb_rr3 {
            key = {
                ig_md.key.filter0 : exact;
                ig_md.key.filter1 : exact;
                ig_md.key.filter2 : exact;
                ig_md.key.filter3 : exact;
                ig_md.key.filter4 : exact;
                ig_md.key.filter5 : exact;
                ig_md.key.filter6 : exact;
            }
            actions = {
                NoAction;
                add_3_0_1;
                add_3_0_2;
                add_3_1_2;
                ass_3_0;
                ass_3_1;
                ass_3_2;
            }
            default_action = NoAction();
        }
        table tb_rr3_reg {
            key = {
                ig_md.key.filter0 : exact;
                ig_md.key.filter1 : exact;
                ig_md.key.filter2 : exact;
                ig_md.key.filter3 : exact;
                ig_md.key.filter4 : exact;
                ig_md.key.filter5 : exact;
                ig_md.key.filter6 : exact;
            }
            actions = {
                NoAction;
                rr3_reg_op0;
                rr3_reg_op1;
                rr3_reg_op2;
                rr3_reg_op3;
            }
            default_action = NoAction();
        }


        apply {
            tb_rr0.apply();
            tb_rr1.apply();
            tb_rr1_reg.apply();
            tb_rr2.apply();
            tb_rr2_reg.apply();
            tb_rr3.apply();
            tb_rr3_reg.apply();
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
        HI() hi;
        AT() at;
        PS() ps;
        KS() ks0;
        KS() ks1;
        RR() rr;
        HM() hm0;
        HM() hm1;



        

        action forward(PortId_t port) {
            ig_intr_tm_md.ucast_egress_port = port;
        }

        action first_recirculate() {
            ig_intr_tm_md.ucast_egress_port = 68;
            hdr.ipv4.rec = 1;
            hdr.rr.setValid();
            hdr.rr.time = 1;
            hdr.rr.port = ig_intr_tm_md.ucast_egress_port;
        }

        action recirculate() {
            hdr.rr.time = hdr.rr.time + 1;
            ig_intr_tm_md.ucast_egress_port = 68;
        }

        action last_recirculate() {
            ig_intr_tm_md.ucast_egress_port = hdr.rr.port;
            hdr.ipv4.rec = 0;
            hdr.rr.setInvalid();
        }

        table tb_forward {
            key = {ig_intr_md.ingress_port : exact;}
            actions = {
                forward;
                NoAction;
            }
            default_action = NoAction();
        }

        table tb_recirculate {
            key = {
                ig_md.key.filter0 : exact;
                ig_md.key.filter1 : exact;
                ig_md.key.filter2 : exact;
                ig_md.key.filter3 : exact;
                ig_md.key.filter4 : exact;
                ig_md.key.filter5 : exact;
                ig_md.key.filter6 : exact;
            }
            actions = {
                first_recirculate;
                last_recirculate;
                recirculate;
                NoAction;
            }
            default_action = NoAction();
        }


        apply {
            //tb_forward.apply();
            fs0.apply(hdr, ig_md, ig_intr_md);
            hi.apply(hdr, ig_md);
            at.apply(hdr, ig_md);
            ps.apply(hdr, ig_md);
            ks0.apply(hdr, ig_md);
            ks1.apply(hdr, ig_md);
            rr.apply(hdr, ig_md);
            hm0.apply(hdr, ig_md, ig_intr_dprsr_md, ig_intr_tm_md);
            hm1.apply(hdr, ig_md, ig_intr_dprsr_md, ig_intr_tm_md);
            tb_recirculate.apply();
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
