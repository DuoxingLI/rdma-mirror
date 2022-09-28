#################################################################################################
# BAREFOOT NETWORKS CONFIDENTIAL & PROPRIETARY
#
# Copyright (c) 2019-present Barefoot Networks, Inc.
#
# All Rights Reserved.
#
# NOTICE: All information contained herein is, and remains the property of
# Barefoot Networks, Inc. and its suppliers, if any. The intellectual and
# technical concepts contained herein are proprietary to Barefoot Networks, Inc.
# and its suppliers and may be covered by U.S. and Foreign Patents, patents in
# process, and are protected by trade secret or copyright law.  Dissemination of
# this information or reproduction of this material is strictly forbidden unless
# prior written permission is obtained from Barefoot Networks, Inc.
#
# No warranty, explicit or implicit is provided, unless granted under a written
# agreement with Barefoot Networks, Inc.
#
################################################################################

import logging
import random

from ptf import config
from collections import namedtuple
import ptf.testutils as testutils
from bfruntime_client_base_tests import BfRuntimeTest
import bfrt_grpc.client as gc
import grpc

logger = logging.getLogger('Test')
if not len(logger.handlers):
    logger.addHandler(logging.StreamHandler())




class RdmaMirrorTest(BfRuntimeTest):
    """@brief Basic test for my sketch.
    """

    def setUp(self):
        client_id = 0
        p4_name = "rdmamirror"
        BfRuntimeTest.setUp(self, client_id, p4_name)

    def runTest(self):
        port_18 = 148
        port_15 = 156
        port_11 = 132
        port_12 = 140
        ig_port = 148
        eg_port = 156

        # Get bfrt_info and set it as part of the test
        bfrt_info = self.interface.bfrt_info_get("rdmamirror")

        forward_table = bfrt_info.table_get("SwitchIngress.table_port_forward")
        # forward_table.info.key_field_annotation_add("hdr.ipv4.dst_addr", "ipv4")
        mirror_cfg_table = bfrt_info.table_get("$mirror.cfg")
        # length_table = bfrt_info.table_get("SwitchEgress.table_judge_short")

        target = gc.Target(device_id=0, pipe_id=0xffff)
        # forward_table.entry_add(
        #     target,
        #     [forward_table.make_key([gc.KeyTuple('hdr.ipv4.dst_addr', "10.0.0.1")])],
        #     [forward_table.make_data([gc.DataTuple('port', eg_port)],'SwitchIngress.hit')]
        # )

        forward_table.entry_add(
            target,
            [forward_table.make_key([gc.KeyTuple('ig_intr_md.ingress_port', port_15)])],
            [forward_table.make_data([gc.DataTuple('port', port_11)],'SwitchIngress.port_forward')]
        )

        forward_table.entry_add(
            target,
            [forward_table.make_key([gc.KeyTuple('ig_intr_md.ingress_port', port_11)])],
            [forward_table.make_data([gc.DataTuple('port', port_15)],'SwitchIngress.port_forward')]
        )
        
        mirror_cfg_table.entry_add(
                    target,
                    [mirror_cfg_table.make_key([gc.KeyTuple('$sid', ig_port)])],
                    [mirror_cfg_table.make_data([gc.DataTuple('$direction', str_val="INGRESS"),
                                                 gc.DataTuple('$ucast_egress_port', ig_port),
                                                 gc.DataTuple('$ucast_egress_port_valid', bool_val=True),
                                                 gc.DataTuple('$session_enable', bool_val=True)],
                                                '$normal')]
                )

        mirror_cfg_table.entry_add(
                    target,
                    [mirror_cfg_table.make_key([gc.KeyTuple('$sid', eg_port)])],
                    [mirror_cfg_table.make_data([gc.DataTuple('$direction', str_val="INGRESS"),
                                                 gc.DataTuple('$ucast_egress_port', eg_port),
                                                 gc.DataTuple('$ucast_egress_port_valid', bool_val=True),
                                                 gc.DataTuple('$session_enable', bool_val=True)],
                                                '$normal')]
                )




        
        # length_table.entry_add(
        #             target,
        #             [length_table.make_key([gc.KeyTuple('eg_intr_md.pkt_length',
        #                                                  low=0,
        #                                                  high=128)])],
        #             [length_table.make_data([],'set_short')]
        # )

        # pkt = testutils.simple_tcp_packet(ip_dst="10.0.0.1")
        # exp_pkt = pkt
        # logger.info("Sending packet on port %d", ig_port)
        # testutils.send_packet(self, ig_port, pkt)

        # logger.info("Expecting packet on port %d", eg_port)  # Change this --> eg_port[0]
        # testutils.verify_packets(self, exp_pkt, [eg_port])

        # # check get
       
        # resp = forward_table.entry_get(
        #     target,
        #     [forward_table.make_key([gc.KeyTuple('hdr.ipv4.dst_addr', "10.0.0.1")])],
        #     {"from_hw": True})

        # data_dict = next(resp)[0].to_dict()
        # recv_port = data_dict["port"]
        # if (recv_port != eg_port):
        #     logger.error("Error! port sent = %s received port = %s", str(eg_port), str(recv_port))
        #     assert 0

        # # delete all entries
 
        # forward_table.entry_del(
        #     target,
        #     [forward_table.make_key([gc.KeyTuple('hdr.ipv4.dst_addr', "10.0.0.1")])])

        # # send pkt and verify dropped
        # pkt = testutils.simple_tcp_packet(ip_dst="10.0.0.1")
        # logger.info("Sending packet on port %d", ig_port)
        # testutils.send_packet(self, ig_port, pkt)
        # logger.info("Packet is expected to get dropped.")
        # testutils.verify_no_other_packets(self)
