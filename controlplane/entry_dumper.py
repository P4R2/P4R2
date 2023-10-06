import bfrt_grpc.client as client
import json
import time
import socket
import re
from runtime import bfrt_runtime



def ipv6_to_byte_array(addr):
    """ Convert Ipv6 address to a bytearray. """
    return socket.inet_pton(socket.AF_INET6, addr)

def ipv4_to_byte_array(addr):
    """ Convert Ipv4 address to a bytearray. """
    if re.match(r'(\d+)\.(\d+)\.(\d+)\.(\d+)', addr):
        return socket.inet_pton(socket.AF_INET, addr)
    else:
        return addr
        

class entry_dumper():
    def __init__(self, p4r2_runtume, config_path="../config.json"):
        self.runtime = p4r2_runtume
        self.entry_info = {}
        with open(config_path, 'r') as fr:
            self.config = json.load(fr)
        self.filtering_dict = {"0" : -1}

    def entry_add(self, info, add=True):

        table_name = info[0]
        if re.search(r'tb_filter_setting\d', info[0]):
            '''
            self.tb = self.bfrt_info.table_get(info[0])

            l = []
            for i in range(info[1]):
                l.append(client.KeyTuple(info[2 + 3*i], ipv4_to_byte_array(info[3 + 3*i]), ipv4_to_byte_array(info[4 + 3*i])))
            key_list = [self.tb.make_key(l)]
            data_list = [self.tb.make_data([client.DataTuple(info[-3], int(info[-2]))], info[-1])]
            if add:
                self.tb.entry_add(self.switch_target, key_list, data_list)
            else:
                self.tb.entry_del(self.switch_target, key_list)
            '''

            key_list = []
            data_list = []
            annotation_list = []

            #predefined key_list
            #Future: rewrite with P4R2 compiler
            '''
            ig_intr_md.ingress_port : ternary;
            hdr.ipv4.dst : ternary;
            hdr.tunnel.dst_id : ternary;
            hdr.cacl.op : ternary;
            hdr.tcp.syn : ternary;
            hdr.nc.key : ternary;
            hdr.nc.op : ternary;
            hdr.rr.info: ternary;
            hdr.rr.time: exact;
            ig_md.key.bitmap : exact;
            '''

            '''
            key_list = [
                #['ig_intr_md.ingress_port', 0, 0, 'ternary'],
                ['hdr.ipv4.dst', 0, 0, 'ternary'],
                #['hdr.tunnel.dst_id', 0, 0, 'ternary'],
                #['hdr.cacl.op', 0, 0, 'ternary'],
                #['hdr.tcp.syn', 0, 0, 'ternary'],
                #['hdr.nc.key', 0, 0, 'ternary'],
                #['hdr.nc.op', 0, 0, 'ternary'],
                #['hdr.rr.info', 0, 0, 'ternary'],
                #['hdr.rr.time', 0, 'exact'],
                ['ig_md.key.bitmap', 0, 'exact']
            ]
            for i in range(info[1]):
                if re.match(r'(\d+)\.(\d+)\.(\d+)\.(\d+)', info[3 + 3*i]):
                    annotation_list.append([info[2 + 3*i], "ipv4"])
                    for j in range(len(key_list)):
                        if key_list[j][0] == info[2+3*i]:
                            key_list[j][1] = info[3 + 3*i]
                            key_list[j][2] = info[4 + 3*i]
                            break
                    #key_list.append([info[2 + 3*i], info[3 + 3*i], info[4 + 3*i], "ternary"])
                else:
                    for j in range(len(key_list)):
                        if key_list[j][0] == info[2+3*i]:
                            key_list[j][1] = int(info[3 + 3*i])
                            key_list[j][2] = int(info[4 + 3*i])
                            break
                    #key_list.append([info[2 + 3*i], int(info[3 + 3*i]), int(info[4 + 3*i]), "ternary"])
            #key_list.append(['hdr.rr.time', int(info[-5]), "exact"])
            #key_list.append(['ig_md.key.bitmap', int(info[-4]), "exact"])

            #key_list[8][1] = int(info[-5])
            #key_list[9][1] = int(info[-4], 2)

            key_list[1][1] = int(info[-4], 2)
            '''

            #print(info)

            for i in range((len(info)-7)/3):
                if re.match(r'(\d+)\.(\d+)\.(\d+)\.(\d+)', info[3 + 3*i]):
                    annotation_list.append([info[2 + 3*i], "ipv4"])
                    key_list.append([info[2+3*i], info[3+3*i], info[4+3*i], "ternary"])
                else:
                    key_list.append([info[2+3*i], int(info[3+3*i]), int(info[4+3*i]), "ternary"])
            
            if int(info[-5]) > 0:
                key_list.append(["hdr.rr.time", int(info[-5]), "exact"])
            key_list.append(['ig_md.key.bitmap', int(info[-4], 2), "exact"])

            #print(key_list)
            data_list = [[[info[-3], int(info[-2])]], info[-1]]

            if add:
                self.filtering_dict[info[-2]] = info[1]
                self.runtime.entry_add(table_name, key_list, data_list, annotation_list)
                if self.entry_info.get(table_name) is None:
                    self.entry_info[table_name] = [key_list]
                else:
                    self.entry_info[table_name].append(key_list)
            else:
                self.filtering_dict.pop(info[-2])
                self.runtime.entry_del(table_name, key_list, annotation_list)
                self.entry_info[table_name].remove(key_list)
                
        elif re.search(r'tb_hashed_index_setting', info[0]):
            '''
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
            '''

            key_list = [['ig_md.key.filter'+ str(i), 0, "exact"] for i in range(len(self.config["parsing_logic"]))]
            key_list[self.filtering_dict[info[1]]][1] = int(info[1])
            data_list = []

            if 'index' in info:
                data_list = [[[info[2], int(info[3])]], info[4]]
            else:
                data_list = [[], info[2]]

            if add:
                self.runtime.entry_add(table_name, key_list, data_list)
                if self.entry_info.get(table_name) is None:
                    self.entry_info[table_name] = [key_list]
                else:
                    self.entry_info[table_name].append(key_list)
            else:
                self.runtime.entry_del(table_name, key_list)
                self.entry_info[table_name].remove(key_list)


        elif re.search(r'tb_rr\d_index_shift', info[0]):
            '''
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
            '''

            key_list = [['ig_md.key.filter'+ str(i), 0, "exact"] for i in range(len(self.config["parsing_logic"]))]
            key_list[self.filtering_dict[info[1]]][1] = int(info[1])
            data_list = [[], info[2]]

            if add:
                self.runtime.entry_add(table_name, key_list, data_list)
                if self.entry_info.get(table_name) is None:
                    self.entry_info[table_name] = [key_list]
                else:
                    self.entry_info[table_name].append(key_list)
            else:
                self.runtime.entry_del(table_name, key_list)
                self.entry_info[table_name].remove(key_list)

        elif re.search(r'tb_rr\d_index_add', info[0]):
            '''
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
            '''
            print(info)
            key_list = [['ig_md.key.filter'+ str(i), 0, "exact"] for i in range(len(self.config["parsing_logic"]))]
            key_list[self.filtering_dict[info[1]]][1] = int(info[1])
            data_list = [[[info[2], int(info[3])]], info[4]]
            print(key_list)
            if add:
                self.runtime.entry_add(table_name, key_list, data_list)
                if self.entry_info.get(table_name) is None:
                    self.entry_info[table_name] = [key_list]
                else:
                    self.entry_info[table_name].append(key_list)
            else:
                self.runtime.entry_del(table_name, key_list)
                self.entry_info[table_name].remove(key_list)
            

        elif re.search(r'tb_key_selection', info[0]):
            '''
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
            '''

            key_list = [['ig_md.key.filter'+ str(i), 0, "exact"] for i in range(len(self.config["parsing_logic"]))]
            key_list[self.filtering_dict[info[1]]][1] = int(info[1])
            data_list = [[], info[2]]

            if add:
                self.runtime.entry_add(table_name, key_list, data_list)
                if self.entry_info.get(table_name) is None:
                    self.entry_info[table_name] = [key_list]
                else:
                    self.entry_info[table_name].append(key_list)
            else:
                self.runtime.entry_del(table_name, key_list)
                self.entry_info[table_name].remove(key_list)

        elif re.search(r'tb_rr\d_parameter_setting', info[0]):
            '''
            self.tb = self.bfrt_info.table_get(info[0])
            key_list = [
                self.tb.make_key([\
                    client.KeyTuple('ig_md.key.filter', int(info[1])),\
                ]), \
            ]
            if len(info) >= 5:
                data_list = [self.tb.make_data([client.DataTuple(info[2], int(info[3]))], info[4])]
            else:
                data_list = [self.tb.make_data([], info[2])]
            if add:
                self.tb.entry_add(self.switch_target, key_list, data_list)
            else:
                self.tb.entry_del(self.switch_target, key_list)
            '''

            key_list = [['ig_md.key.filter'+ str(i), 0, "exact"] for i in range(len(self.config["parsing_logic"]))]
            key_list[self.filtering_dict[info[1]]][1] = int(info[1])
            data_list = []

            if len(info) >= 5:
                data_list = [[[info[2], int(info[3])]], info[4]]
            else:
                data_list = [[], info[2]]

            if add:
                self.runtime.entry_add(table_name, key_list, data_list)
                if self.entry_info.get(table_name) is None:
                    self.entry_info[table_name] = [key_list]
                else:
                    self.entry_info[table_name].append(key_list)
            else:
                self.runtime.entry_del(table_name, key_list)
                self.entry_info[table_name].remove(key_list)

        elif re.search(r'tb_header_modifier', info[0]):
            '''
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
            '''

            key_list = [['ig_md.key.filter'+ str(i), 0, "exact"] for i in range(len(self.config["parsing_logic"]))]
            key_list[self.filtering_dict[info[1]]][1] = int(info[1])
            data_list = [[], info[2]]

            if add:
                self.runtime.entry_add(table_name, key_list, data_list)
                if self.entry_info.get(table_name) is None:
                    self.entry_info[table_name] = [key_list]
                else:
                    self.entry_info[table_name].append(key_list)
            else:
                self.runtime.entry_del(table_name, key_list)
                self.entry_info[table_name].remove(key_list)


        elif re.search(r'tb_rr\d_reg', info[0]):
            '''
            self.tb = self.bfrt_info.table_get(info[0])
            key_list = [
                self.tb.make_key([\
                    client.KeyTuple('ig_md.key.filter', int(info[1])),\
                    client.KeyTuple('ig_md.key.lock', 0),\
                ]), \
            ]
            data_list = [self.tb.make_data([], info[2])]
            if add:
                self.tb.entry_add(self.switch_target, key_list, data_list)
            else:
                self.tb.entry_del(self.switch_target, key_list)
            '''

            key_list = [['ig_md.key.filter'+ str(i), 0, "exact"] for i in range(len(self.config["parsing_logic"]))]
            key_list[self.filtering_dict[info[1]]][1] = int(info[1])
            data_list = [[], info[2]]

            if add:
                self.runtime.entry_add(table_name, key_list, data_list)
                if self.entry_info.get(table_name) is None:
                    self.entry_info[table_name] = [key_list]
                else:
                    self.entry_info[table_name].append(key_list)
            else:
                self.runtime.entry_del(table_name, key_list)
                self.entry_info[table_name].remove(key_list)


        elif re.search(r'tb_rr\d', info[0]):
            '''
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
            '''

            key_list = [['ig_md.key.filter'+ str(i), 0, "exact"] for i in range(len(self.config["parsing_logic"]))]
            key_list[self.filtering_dict[info[1]]][1] = int(info[1])
            if len(info) == 3:
                data_list = [[], info[2]]
            else:
                data_list = [[[info[3], int(info[4])]], info[2]]

            if add:
                self.runtime.entry_add(table_name, key_list, data_list)
                if self.entry_info.get(table_name) is None:
                    self.entry_info[table_name] = [key_list]
                else:
                    self.entry_info[table_name].append(key_list)
            else:
                self.runtime.entry_del(table_name, key_list)
                self.entry_info[table_name].remove(key_list)
        
        elif re.search(r'rec', info[0]):
            '''
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
            '''

            key_list = [['ig_md.key.filter'+ str(i), 0, "exact"] for i in range(len(self.config["parsing_logic"]))]
            key_list[self.filtering_dict[info[1]]][1] = int(info[1])
            data_list = [[], info[2]]

            if add:
                self.runtime.entry_add(table_name, key_list, data_list)
                if self.entry_info.get(table_name) is None:
                    self.entry_info[table_name] = [key_list]
                else:
                    self.entry_info[table_name].append(key_list)
            else:
                self.runtime.entry_del(table_name, key_list)
                self.entry_info[table_name].remove(key_list)

    def lock(self, filter_id):
        '''
        self.tb = self.bfrt_info.table_get('SwitchIngress.tb_set_lock_id')
        key_list = [self.tb.make_key([client.KeyTuple('ig_md.useless_key', 0)])]
        data_list = [self.tb.make_data([client.DataTuple('lock_id', self.filterID)], 'set_lock_id')]
        self.tb.entry_add(self.switch_target, key_list, data_list)
        '''

        table_name = "SwitchIngress.tb_set_lock_id"
        key_list = [['ig_md.useless_key', 0, "exact"]]
        data_list = [[["lock_id", filter_id]], "set_lock_id"]
        self.runtime.entry_add(table_name, key_list, data_list)
        self.entry_info[table_name] = [key_list]

    def unlock(self):
        '''
        self.tb = self.bfrt_info.table_get('SwitchIngress.tb_set_lock_id')
        key_list = [self.tb.make_key([client.KeyTuple('ig_md.useless_key', 0)])]
        self.tb.entry_del(self.switch_target, key_list)
        '''

        table_name = "SwitchIngress.tb_set_lock_id"
        key_list = [['ig_md.useless_key', 0, "exact"]]
        self.runtime.entry_del(table_name, key_list)
        self.entry_info[table_name] = []


    def dump(self, infos):
        '''
        infos_group = {}
        for info in infos:
            if re.search(r'tb_filter_setting', info[0]):
                filter_id = info[-2]
            else:
                filter_id = info[1]
            if infos_group.get(filter_id) is None:
                infos_group[filter_id] = [info]
            else:
                infos_group[filter_id].append(info)
        
        #print(infos_group)
        
        for filrer_id, infos in infos_group.items():
            #print(filrer_id, infos)
            self.lock(int(filrer_id))
            for i in infos:
                if i[-1] == 'del':
                    i.pop()
                    self.entry_add(i, False)
                else:
                    self.entry_add(i)
            self.unlock()
        '''

        #without locking
        for i in infos:
            if i[-1] == 'del':
                i.pop()
                self.entry_add(i, False)
            else:
                    self.entry_add(i)

    
    def clear_all(self):
        for table_name, key_lists in self.entry_info.items():
            for key_list in key_lists:
                 self.runtime.entry_del(table_name, key_list)
        self.entry_info.clear()



