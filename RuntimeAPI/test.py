from atexit import register
import logging
from ptf import config
from bfruntime_client_base_tests import BfRuntimeTest
import bfrt_grpc.client as client
import json
import grpc
from pal_rpc.ttypes import *
from ptf.testutils import *
from ptf.thriftutils import *
import ptf.dataplane as dataplane
import bfrt_grpc.bfruntime_pb2 as bfruntime_pb2
from ptf_port import *
from scapy.all import *
import time
from ipaddress import ip_address
import socket
import re
from rpc import *



t = []

modules = [
    "FS",
    "IS",
    "KS",
    "AR",
    "HM"
]

table_name_dict = {
    "FS": ["SwitchIngress.fs.tb_filter_setting"],
    "IS": ["SwitchIngress.hi.tb_hashed_index_setting", 
            "SwitchIngress.at.tb_index_shift",
            "SwitchIngress.at.tb_index_add"],
    "KS": ["SwitchIngress.at.tb_key_selection"],
    "AR": ["SwitchIngress.rr.tb_rr"],
    "HM": ["SwitchIngress.hm.tb_header_modifier"]
}


port_dict = {
    '33/0': 64,
    '33/1': 65,
    '14/0': 16,
    '16/0': 0,
    '2/0': 140
}


def ipv6_to_byte_array(addr):
    """ Convert Ipv6 address to a bytearray. """
    return socket.inet_pton(socket.AF_INET6, addr)

def ipv4_to_byte_array(addr):
    """ Convert Ipv4 address to a bytearray. """
    if re.match(r'(\d+)\.(\d+)\.(\d+)\.(\d+)', addr):
        return socket.inet_pton(socket.AF_INET, addr)
    else:
        return addr
        
def ipv4_to_int(addr):
    if re.match(r'(\d+)\.(\d+)\.(\d+)\.(\d+)', addr):
        res = re.match(r'(\d+)\.(\d+)\.(\d+)\.(\d+)', addr)
        return int(res.group(1)) * 2**24 + int(res.group(2)) * 2**16 + int(res.group(3)) * 2**8 + int(res.group(4))
    else:
        return int(addr)

logger = logging.getLogger('Test')
if not len(logger.handlers): 
    logger.addHandler(logging.StreamHandler())

dev_ports_10g = []
dev_ports_40g = []
class BaselineTest(BfRuntimeTest):
    """@brief a simple p4 program containing
    a m-a forward table and a digest mechanism
    """
    p4_name = None
    switch_target = None
    bfrt_info = None
    forward_table = None
    port_table = None


    def setUp(self):
        print "here0"
        client_id = 0
        self.p4_name = "rr"
        BfRuntimeTest.setUp(self, client_id, self.p4_name)

    def add10GPort(self, port):
        self.port_table.entry_add(
            self.switch_target,
            [self.port_table.make_key([client.KeyTuple('$DEV_PORT', port)])],
            [self.port_table.make_data([
                client.DataTuple('$SPEED', str_val="BF_SPEED_10G"),
		        client.DataTuple('$AUTO_NEGOTIATION', 2),
                client.DataTuple('$PORT_ENABLE', bool_val=True),
                client.DataTuple('$FEC', str_val="BF_FEC_TYP_NONE")])])

    def add40GPort(self, port):
        self.port_table.entry_add(
            self.switch_target,
            [self.port_table.make_key([client.KeyTuple('$DEV_PORT', port)])],
            [self.port_table.make_data([
                client.DataTuple('$SPEED', str_val="BF_SPEED_40G"),
		        client.DataTuple('$AUTO_NEGOTIATION', 0),
                client.DataTuple('$PORT_ENABLE', bool_val=True),
                client.DataTuple('$FEC', str_val="BF_FEC_TYP_NONE")])])

    def entry_add(self, info, add=True):
        if re.search(r'tb_filter_setting', info[0]):
            self.tb = self.bfrt_info.table_get(info[0])

            l = []
            for i in range(info[1]):
                l.append(client.KeyTuple(info[2 + 3*i], ipv4_to_int(info[3 + 3*i]), ipv4_to_int(info[4 + 3*i])))
            key_list = [self.tb.make_key(l)]
            data_list = [self.tb.make_data([client.DataTuple(info[-3], int(info[-2]))], info[-1])]
            if add:
                self.tb.entry_add(self.switch_target, key_list, data_list)
            else:
                self.tb.entry_del(self.switch_target, key_list)

        elif re.search(r'tb_hashed_index_setting', info[0]):
            self.tb = self.bfrt_info.table_get(info[0])
            if 'index' in info:
                key_list = [
                    self.tb.make_key([\
                        client.KeyTuple('ig_md.key.filter', int(info[1])),\
                    ]), \
                ]
                data_list = [self.tb.make_data([client.DataTuple(info[2], int(info[3]))], info[4])]
            else:
                key_list = [
                    self.tb.make_key([\
                        client.KeyTuple('ig_md.key.filter', int(info[1])),\
                    ]), \
                ]
                data_list = [self.tb.make_data([], info[2])]
            if add:
                self.tb.entry_add(self.switch_target, key_list, data_list)
            else:
                self.tb.entry_del(self.switch_target, key_list)

        elif re.search(r'tb_index_shift', info[0]):
            self.tb = self.bfrt_info.table_get(info[0])
            key_list = [
                self.tb.make_key([\
                    client.KeyTuple('ig_md.key.filter', int(info[1])),\
                ]), \
            ]
            data_list = [self.tb.make_data([], info[2])]
            if add:
                self.tb.entry_add(self.switch_target, key_list, data_list)
            else:
                self.tb.entry_del(self.switch_target, key_list)

        elif re.search(r'tb_index_add', info[0]):
            self.tb = self.bfrt_info.table_get(info[0])
            key_list = [
                self.tb.make_key([\
                    client.KeyTuple('ig_md.key.filter', int(info[1])),\
                ]), \
            ]
            data_list = [self.tb.make_data([client.DataTuple(info[2], int(info[3]))], info[4])]
            if add:
                self.tb.entry_add(self.switch_target, key_list, data_list)
            else:
                self.tb.entry_del(self.switch_target, key_list)

        elif re.search(r'tb_key_selection', info[0]):
            self.tb = self.bfrt_info.table_get(info[0])
            key_list = [
                self.tb.make_key([\
                    client.KeyTuple('ig_md.key.filter', int(info[1])),\
                ]), \
            ]
            data_list = [self.tb.make_data([], info[2])]
            if add:
                self.tb.entry_add(self.switch_target, key_list, data_list)
            else:
                self.tb.entry_del(self.switch_target, key_list)

        elif re.search(r'tb_rr', info[0]):
            self.tb = self.bfrt_info.table_get(info[0])
            key_list = [
                self.tb.make_key([\
                    client.KeyTuple('ig_md.key.filter', int(info[1])),\
                ]), \
            ]
            data_list = [self.tb.make_data([], info[2])]
            if add:
                self.tb.entry_add(self.switch_target, key_list, data_list)
            else:
                self.tb.entry_del(self.switch_target, key_list)

        elif re.search(r'tb_parameter_setting', info[0]):
            self.tb = self.bfrt_info.table_get(info[0])
            key_list = [
                self.tb.make_key([\
                    client.KeyTuple('ig_md.key.filter', int(info[1])),\
                ]), \
            ]
            data_list = [self.tb.make_data([client.DataTuple(info[2], int(info[3]))], info[4])]
            if add:
                self.tb.entry_add(self.switch_target, key_list, data_list)
            else:
                self.tb.entry_del(self.switch_target, key_list)

        elif re.search(r'tb_header_modifier', info[0]):
            self.tb = self.bfrt_info.table_get(info[0])
            key_list = [
                self.tb.make_key([\
                    client.KeyTuple('ig_md.key.filter', int(info[1])),\
                ]), \
            ]
            data_list = [self.tb.make_data([], info[2])]
            if add:
                self.tb.entry_add(self.switch_target, key_list, data_list)
            else:
                self.tb.entry_del(self.switch_target, key_list)

    def parse_command(self, s):
        if re.match(r'\s*dump\s+(.*?)\s+(\d+)\s*', s):
            res = re.match(r'\s*dump\s+(.*?)\s+(\d+)\s*', s)
            t.append(time.time())
            infos = self.cp.start(res.group(1), int(res.group(2)))
            t.append(time.time())
            for i in infos:
                if i[-1] == 'del':
                    i.pop()
                    self.entry_add(i, False)
                else:
                    self.entry_add(i)
            t.append(time.time())
        elif re.match(r'\s*help\s*', s):
            print('\tHelp: type \'quit\' or \'q\' to quit')
            print('\t      type \'dump --filepath --p\' to parse primitives and dump entries')
        else:
            print('unknown command, type \'help\' for help')

    def runTest(self):      
        self.bfrt_info = self.interface.bfrt_info_get(self.p4_name) 
        self.switch_target = client.Target(device_id=0, pipe_id=0xffff)


        self.cp = RPC()

        print('\t----P4R2 Runtime API----\t')
        print('\tHelp: type \'quit\' or \'q\' to quit')
        print('\t      type \'dump --filepath --p\' to parse primitives and dump entries')
        while True:
            command = input()
            if command == 'quit' or command == 'q':
                break
            else:
                self.parse_command(command)
                print('reconfiguration done')
                print('primitive parsing time:' + str((t[-2]-t[-3])*1000) + 'ms')
                print('entry dumping time:' + str((t[-1]-t[-2])*1000) + 'ms')





'''
        packets = sniff(iface = 'enp4s0', prn=check_and_delay)
        while True:
            pass
'''
