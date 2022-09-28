/*******************************************************************************
 * BAREFOOT NETWORKS CONFIDENTIAL & PROPRIETARY
 *
 * Copyright (c) 2019-present Barefoot Networks, Inc.
 *
 * All Rights Reserved.
 *
 * NOTICE: All information contained herein is, and remains the property of
 * Barefoot Networks, Inc. and its suppliers, if any. The intellectual and
 * technical concepts contained herein are proprietary to Barefoot Networks, Inc.
 * and its suppliers and may be covered by U.S. and Foreign Patents, patents in
 * process, and are protected by trade secret or copyright law.  Dissemination of
 * this information or reproduction of this material is strictly forbidden unless
 * prior written permission is obtained from Barefoot Networks, Inc.
 *
 * No warranty, explicit or implicit is provided, unless granted under a written
 * agreement with Barefoot Networks, Inc.
 *
 ******************************************************************************/

#include <core.p4>
#if __TARGET_TOFINO__ == 2
#include <t2na.p4>
#else
#include <tna.p4>
#endif

#include "common/headers.p4"
#include "common/util.p4"



#if __TARGET_TOFINO__ == 1
typedef bit<3> mirror_type_t;
#else
typedef bit<4> mirror_type_t;
#endif
const mirror_type_t MIRROR_TYPE_I2E = 1;
const mirror_type_t MIRROR_TYPE_E2E = 2;


struct metadata_t {
    bit<32> written_value;
    bit<32> marked_psn; 
    bit<32> curr_seq;
    bit<32> the_psn;
    bit<7> rand_num;
    bit<11> rand_num2;
    bit<1> is_short;

    bit<1> do_ing_mirroring;  // Enable ingress mirroring
    MirrorId_t ing_mir_ses;   // Ingress mirror session ID
    pkt_type_t pkt_type;
}


// ---------------------------------------------------------------------------
// Ingress parser
// ---------------------------------------------------------------------------
parser SwitchIngressParser(
        packet_in pkt,
        out header_t hdr,
        out metadata_t ig_md,
        out ingress_intrinsic_metadata_t ig_intr_md) {
    TofinoIngressParser() tofino_parser;

    state start {
        tofino_parser.apply(pkt, ig_intr_md);
        transition parse_ethernet;
    }

    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        // transition accept;
        transition select(hdr.ethernet.ether_type) {
            ETHERTYPE_IPV4 : parse_ipv4;
            default : accept;
        }
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            IP_PROTOCOLS_UDP : parse_udp;
            IP_PROTOCOLS_TCP : accept;
            default : accept;
        }
    }

    state parse_udp {
        pkt.extract(hdr.udp);
        transition select(hdr.udp.dst_port) {
            4791: parse_ib;
            default : accept;
        }
    }

    state parse_ib {
        pkt.extract(hdr.ib);
        transition select(hdr.ib.opcode) {
            17: parse_aeth;
            default : accept;
        }
    }

    state parse_aeth {
        pkt.extract(hdr.aeth);
        transition accept;
    }

}

// ---------------------------------------------------------------------------
// Ingress Deparser
// ---------------------------------------------------------------------------
control SwitchIngressDeparser(
        packet_out pkt,
        inout header_t hdr,
        in metadata_t ig_md,
        in ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md) {

    Mirror() mirror;
    apply {

        if (ig_dprsr_md.mirror_type == MIRROR_TYPE_I2E) {
            mirror.emit<mirror_h>(ig_md.ing_mir_ses, {ig_md.pkt_type});
            // mirror.emit(ig_md.ing_mir_ses)
        
        }

        pkt.emit(hdr);
    }
}

control SwitchIngress(
        inout header_t hdr,
        inout metadata_t ig_md,
        in ingress_intrinsic_metadata_t ig_intr_md,
        in ingress_intrinsic_metadata_from_parser_t ig_prsr_md,
        inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
        inout ingress_intrinsic_metadata_for_tm_t ig_tm_md) {

    // Random<bit<6>>() rand;
    Register<bit<32>, bit<32>>(32w8, 0) count_reg;
    // A simple dual-width 32-bit register action that will increment the two
    // 32-bit sections independently and return the value of one half before the
    // modification.
    RegisterAction<bit<32>, bit<32>, bit<32>>(count_reg) count_reg_action = {
        void apply(inout bit<32> value, out bit<32> read_value){
            read_value = value;
            value = value + 1;
        }
    };

    Register<bit<32>, bit<32>>(32w8, 0) psn_reg;
    RegisterAction<bit<32>, bit<32>, bit<32>>(psn_reg) psn_reg_read = {
        void apply(inout bit<32> value, out bit<32> read_value){
            read_value = value;
        }
    };

    RegisterAction<bit<32>, bit<32>, bit<32>>(psn_reg) psn_reg_write = {
        void apply(inout bit<32> value, out bit<32> read_value){
            value=ig_md.written_value;
            read_value = value;
        }
    };

    action set_mirror_type() {
        ig_dprsr_md.mirror_type = MIRROR_TYPE_I2E;
        ig_md.pkt_type = PKT_TYPE_MIRROR;
    }

    action set_normal_pkt() {
        hdr.bridged_md.setValid();
        hdr.bridged_md.pkt_type = PKT_TYPE_NORMAL; 
        
    }

    action port_forward(PortId_t port) {
        ig_tm_md.ucast_egress_port=port;
        ig_md.ing_mir_ses=(bit<10>)port;
        
        // ig_tm_md.bypass_egress=1;
    }

    action _drop(){
        ig_dprsr_md.drop_ctl = 0x1;
    }
    table  table_port_forward{
        
        key = {
            ig_intr_md.ingress_port:   exact;
        }
        actions = {
            port_forward;
            _drop;
        }
        size = 512;
        default_action = _drop;
    }


    action action_write_psn_reg(){
        //drop 10th packet
        // ig_md.written_value = 32w88;
        psn_reg_write.execute(1);
    }

    action action_read_psn(){
        ig_md.marked_psn = psn_reg_read.execute(1);
    }

    
    apply {
        // reg_match.apply();
        // reg_match_dir.apply();

        // bit<32> idx_count = 1;
        // bit<32> idx_psn = 2;

        // Purposely assigning bypass_egress field like this so that the
        // compiler generates a match table internally for this register
        // table. (Note that this internally generated table is not
        // published in bf-rt.json but is only published in context.json)

        // ig_tm_md.bypass_egress = bool_register_table_action.execute(idx_);

        //ldx code here
        
        if(!hdr.ib.isValid()){
            table_port_forward.apply();
        }
        else{
            ig_md.written_value = (bit<32>)hdr.ib.psn;
            if(hdr.aeth.isValid()){
                //ack forward directly
                if(hdr.aeth.opcode == 3){
                    action_write_psn_reg();
                    set_mirror_type();
                }
                table_port_forward.apply();

            }
            else{
                //not ack
                ig_md.marked_psn = psn_reg_read.execute(1);
                if(ig_md.marked_psn==ig_md.written_value){
                    set_mirror_type();
                }
                table_port_forward.apply();
            }
        }
        set_normal_pkt();

        // table_port_forward.apply();
    }
}

// ---------------------------------------------------------------------------
// Egress parser
// ---------------------------------------------------------------------------
parser SwitchEgressParser(
        packet_in pkt,
        out header_t hdr,
        out metadata_t eg_md,
        out egress_intrinsic_metadata_t eg_intr_md) {

    TofinoEgressParser() tofino_parser;

    state start {
        tofino_parser.apply(pkt, eg_intr_md);
        transition parse_metadata;
    }

    state parse_metadata {
        mirror_h mirror_md = pkt.lookahead<mirror_h>();
        transition select(mirror_md.pkt_type) {
            PKT_TYPE_MIRROR : parse_mirror_md;
            PKT_TYPE_NORMAL : parse_bridged_md;
            default : accept;
        }
    }

    state parse_bridged_md {
        pkt.extract(hdr.bridged_md);
        transition parse_ethernet;
    }

    state parse_mirror_md {
        mirror_h mirror_md;
        pkt.extract(mirror_md);
        transition parse_ethernet;
    }

    // state parse_ethernet {
    //     pkt.extract(hdr.ethernet);
    //     transition accept;
    // }
    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        // transition accept;
        transition select(hdr.ethernet.ether_type) {
            ETHERTYPE_IPV4 : parse_ipv4;
            default : accept;
        }
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            IP_PROTOCOLS_UDP : parse_udp;
            IP_PROTOCOLS_TCP : accept;
            default : accept;
        }
    }

    state parse_udp {
        pkt.extract(hdr.udp);
        transition select(hdr.udp.dst_port) {
            4791: parse_ib;
            default : accept;
        }
    }

    state parse_ib {
        pkt.extract(hdr.ib);
        transition select(hdr.ib.opcode) {
            17: parse_aeth;
            default : accept;
        }
    }

    state parse_aeth {
        pkt.extract(hdr.aeth);
        transition accept;
    }

}

// ---------------------------------------------------------------------------
// Egress Deparser
// ---------------------------------------------------------------------------
control SwitchEgressDeparser(
        packet_out pkt,
        inout header_t hdr,
        in metadata_t eg_md,
        in egress_intrinsic_metadata_for_deparser_t eg_dprsr_md) {

    // Mirror() mirror;

    apply {

        // if (eg_dprsr_md.mirror_type == MIRROR_TYPE_E2E) {
        //     mirror.emit<mirror_h>(eg_md.egr_mir_ses, {eg_md.pkt_type});
        // }
        
        pkt.emit(hdr);

    }
}

// ---------------------------------------------------------------------------
// Switch Egress MAU
// ---------------------------------------------------------------------------
control SwitchEgress(
        inout header_t hdr,
        inout metadata_t eg_md,
        in    egress_intrinsic_metadata_t                 eg_intr_md,
        in    egress_intrinsic_metadata_from_parser_t     eg_prsr_md,
        inout egress_intrinsic_metadata_for_deparser_t    eg_dprsr_md,
        inout egress_intrinsic_metadata_for_output_port_t eg_oport_md) {

    Random<bit<7>>() rand;
    Random<bit<11>>() rand2;

    action _drop(){
        eg_dprsr_md.drop_ctl = 0x1;
    }

    action no_action(){

    }

    table table_rand_drop {
        key = {
            eg_md.rand_num:  exact;
        }
        actions = {
            _drop;
            no_action;
        }
        const entries = {
			7w5: _drop();
		}
        default_action = no_action;
        size = 1;
    }

    table table_rand_ack {
        key = {
            eg_md.rand_num2:  exact;
        }
        actions = {
            _drop;
            no_action;
        }
        const entries = {
			11w100: _drop();
		}
        default_action = no_action;
        size = 1;
    }

    action set_short(){
        eg_md.is_short = 1;
    }
    action set_n_short(){
        eg_md.is_short = 0;
    }

    table table_judge_short{
        key = {
            eg_intr_md.pkt_length:   range;
        }
        actions = {
            set_short;
            set_n_short;
        }
        // const entries = {
        //     ("eg_intr_md.pkt_length",low = 16w0,high = 16w128 ): set_short();
        // }
        size = 1;
        default_action = set_n_short;
    }

    apply {
        // eg_md.rand_num=rand.get();
        // eg_md.rand_num2=rand2.get();

        // table_judge_short.apply();
        
        // if(eg_md.is_short==1){
        //     table_rand_ack.apply();
        // }
        // else{
        //     table_rand_drop.apply();
        // }
        // if(hdr.bridged_md.isValid()){
        //     hdr.bridged_md.setInvalid();
        // }
    }
}

Pipeline(SwitchIngressParser(),
         SwitchIngress(),
         SwitchIngressDeparser(),
         SwitchEgressParser(),
         SwitchEgress(),
         SwitchEgressDeparser()) pipe;

Switch(pipe) main;
