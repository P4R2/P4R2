//== Metadata definition

struct temp_metadata_t {
    bit<32> temp0;
    bit<32> temp1;
    bit<32> temp2;
    bit<32> temp3;
}

struct key_metadat_t {
    bit<16> filter0;
    bit<16> filter1;
    bit<16> filter2;
    bit<16> filter3;
    bit<16> filter4;
    bit<16> filter5;
    bit<16> filter6;
    bit<16> hash_index0;
    bit<16> hash_index1;
    bit<16> hash_index2;
    bit<16> rr0_register_index;
    bit<16> rr1_register_index;
    bit<16> rr2_register_index;
    bit<16> rr3_register_index;
    bit<8> bitmap;
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