# -*- coding:UTF-8 -*-
import os
import logging
import time
import traceback
import json
import cmd
import argparse
import ipaddress
import prettytable as pt
import sys

import bfrt_grpc.client as gc



class bfrt_runtime():
    '''
    class for runtime control plane
    meneber variables:
     - interface grpc interface
     - target switch target
     - bfrt_info data plane information
     - table table instance in data plane
     - register register instance in data plane
    '''

    def __init__(self, client_id, p4_name):
        self.table = None
        self.register = None
        try:
            self.grpc_setup(client_id, p4_name)
        except Exception as e:
                print(traceback.format_exc())
                exit(1)
        print("connect successfully!")
        print("p4 program: " + p4_name)
        print("client id: " + str(client_id))
        print("\n")
    


    def grpc_setup(self, client_id=0, p4_name=None):
        '''
        Set up connection to gRPC server and bind
        Args: 
            - client_id Client ID
            - p4_name Name of P4 program
        '''
        self.bfrt_info = None

        grpc_addr = 'localhost:50052'        

        self.interface = gc.ClientInterface(grpc_addr, client_id=client_id,
                device_id=0, notifications=None, perform_subscribe=True)
        self.interface.bind_pipeline_config(p4_name)
        self.bfrt_info = self.interface.bfrt_info_get()

        self.target = gc.Target(device_id=0, pipe_id=0xffff)

    def entry_add(self, table_name, key_list, data_list, annotation=None):
        '''
        add a table entry
        Args: 
            - table_name entire table name, e.g. SwitchIngress.control_block_name.table_name
            - key_list a list of indefinite length includes table key_name, key_value, and match_type , e.g. [["hdr.ipv4.src", "0.0.0.1", "exact"], ["hdr.ipv4.src", "0.0.0.1", "0.0.0.0", "ternary"], ["hdr.ipv4.src", 0, 255, "range"], ...]
            - data_list a one-item list includes a list of [table action data_name and data_value](maybe empty) and action_name, e.g. [[[data_name, data_value], ...], action_name] or [[], action_name]
            - annotation list of annotations, e.g. [["hdr.ipv4.src_addr", "ipv4"], ...]
        '''
        self.table = self.bfrt_info.table_get(table_name)
        if annotation:
            for ann in annotation:
                self.table.info.key_field_annotation_add(ann[0], ann[1])

        match = []
        for key in key_list:
            if key[-1] == "exact":
                match.append(gc.KeyTuple(key[0], key[1]))
            if key[-1] == "ternary":
                match.append(gc.KeyTuple(key[0], key[1], key[2]))
            if key[-1] == "range":
                match.append(gc.KeyTuple(key[0], low=key[1], high=key[2]))

        action = []

        if len(data_list[0]) != 0:
            for data in data_list[0]:
                action.append(gc.DataTuple(data[0], data[1]))


        self.table.entry_add(self.target, [self.table.make_key(match)], [self.table.make_data(action, data_list[1])])

    def entry_del(self, table_name, key_list, annotation=None):
        self.table = self.bfrt_info.table_get(table_name)
        if annotation:
            for ann in annotation:
                self.table.info.key_field_annotation_add(ann[0], ann[1])

        match = []
        for key in key_list:
            if key[-1] == "exact":
                match.append(gc.KeyTuple(key[0], key[1]))
            if key[-1] == "ternary":
                match.append(gc.KeyTuple(key[0], key[1], key[2]))
            if key[-1] == "range":
                match.append(gc.KeyTuple(key[0], low=key[1], high=key[2]))
    
        self.table.entry_del(self.target, [self.table.make_key(match)])

    def reg_read(self, reg_name, index):
        '''
        read one block's value of a register
        Args: 
            - reg_name entire register name, e.g. SwitchIngress.control_block_name.reg_name
            - index register index
        retuen a int value
        '''

        self.register = self.bfrt_info.table_get(reg_name)
        snap = self.register.entry_get(self.target, [self.register.make_key([gc.KeyTuple('$REGISTER_INDEX', index)])],{"from_hw": True})
        data, _ = next(snap)
        data_dict = data.to_dict()
        value = data_dict[reg_name + ".f1"][0]
        return value

    def reg_read_range(self, reg_name, low=0, high=0):
        '''
        read a range of values of a register

        return a list of value from reg[low] to reg[high-1]
        '''

        self.register = self.bfrt_info.table_get(reg_name)
        value_list = []
        for i in range(low, high):
            print(1)
            snap = self.register.entry_get(self.target, [self.register.make_key([gc.KeyTuple('$REGISTER_INDEX', i)])],{"from_hw": True})
            data, _ = next(snap)
            data_dict = data.to_dict()
            value = data_dict[reg_name + ".f1"][0]
            value_list.append(value)
        return value_list
        