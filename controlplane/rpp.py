import re
import json

def search_index(item, list):
    for i in range(len(list)):
        if item == list[i]:
            return i
    return -1

class RPP():

    def __init__(self, config_path="../config.json"):
        self.file_path = None
        self.f = None
        self.p = 0
        with open(config_path, 'r') as fr:
            self.config = json.load(fr)
        #print(config)
        self.actions = 'ass|add|sub|mul|and|or|not|addi|andi|ori|xori|register_add|register_sub|register_and|register_or|register_read|register_write|register_max' 

    def error(self, s, n=None):
        es = 'error:\t'
        if n:
            es = es + 'line' + str(n) + '\t'
        es = es + s
        print(es)

    def start(self, fp, p):
        self.file_path = fp
        self.f = open(fp, 'r')
        self.p = p
        infos = self.parse_line()
        self.f.close()
        return infos

    def parse_primitive_arg(self, s, num=None):
        args = s.split(',')
        if num:
            if len(args) != num:
                self.error('the number of parameters does not match', self.line_num)
        for i in range(len(args)):
            args[i] = args[i].strip()
        return args

    def parse_FS(self, res):
        args = self.parse_primitive_arg(res.group(2))
        '''
        pre0 = 'SwitchIngress.fs' + res.group(1) + '.'
        rt_info0 = [pre0 + 'tb_filter_setting']
        rt_info0.append((len(args)-3)/3)
        for i in range(len(args)-3):
            rt_info0.append(args[i])
        rt_info0.append(args[-3])
        rt_info0.append(args[-2])
        rt_info0.append('filterID')
        rt_info0.append(args[-1])
        rt_info0.append(pre0 + 'set_filter')
        if self.d:
            rt_info0.append('del')
        '''
        pre0 = 'SwitchIngress.fs' + res.group(1) + '.'
        bitmap = self.config["bitmap"]
        filtering_keys = self.config["filtering_field"]
        filter_num = search_index(args[-2], bitmap)
        rt_info0 = [pre0 + 'tb_filter_setting' + str(filter_num)]
        rt_info0.append(filter_num)
        for key in filtering_keys[filter_num]:
            rt_info0.append(str(key))
            if key in args: 
                idx = search_index(key, args)
                rt_info0.append(args[idx+1])
                rt_info0.append(args[idx+2])
            else:
                rt_info0.append('0')
                rt_info0.append('0')
        rt_info0.append(args[-3])
        rt_info0.append(args[-2])
        rt_info0.append('filterID')
        rt_info0.append(args[-1])
        rt_info0.append(pre0 + 'set_filter' + str(filter_num))
        if self.d:
            rt_info0.append('del')
        return [rt_info0]

    def parse_IS(self, res):
        args = self.parse_primitive_arg(res.group(2), 4)

        pre0 = 'SwitchIngress.hi.'
        rt_info0 = [pre0 + 'tb_hashed_index' + res.group(1) + '_setting']
        rt_info0.append(args[3])
        rt_info0.append(pre0 + 'set_index' + res.group(1) + '_' + re.sub(r'(\.)', '', args[0]))

        pre1 = 'SwitchIngress.at.'
        rt_info1 = [pre1 + 'tb_rr' + str(self.module_info[3]-1-int(res.group(1))) + '_index_shift']
        rt_info1.append(args[3])
        rt_info1.append(pre1 + 'rr' + str(self.module_info[3]-1-int(res.group(1))) + '_shift_' + args[1])

        rt_info2 = [pre1 + 'tb_rr' + str(self.module_info[3]-1-int(res.group(1)))+ '_index_add']
        rt_info2.append(args[3])
        rt_info2.append('i')
        rt_info2.append(args[2])
        rt_info2.append(pre1 + 'rr' + str(self.module_info[3]-1-int(res.group(1)))  + '_add')

        if self.d:
            rt_info0.append('del')
            rt_info1.append('del')
            rt_info2.append('del')
        if int(args[1]) == 0:
            return [rt_info0, rt_info2]
        return [rt_info0, rt_info1, rt_info2]
    
    def parse_ISM(self, res):
        args = self.parse_primitive_arg(res.group(2), 2)

        pre0 = 'SwitchIngress.hi.'
        rt_info0 = [pre0 + 'tb_hashed_index' + res.group(1) + '_setting']
        rt_info0.append(args[1])
        rt_info0.append('index')
        rt_info0.append(args[0])
        rt_info0.append(pre0 + 'set_index' + res.group(1) + '_manually')

        pre1 = 'SwitchIngress.at.'
        rt_info1 = [pre1 + 'tb_rr' + str(self.module_info[3]-1-int(res.group(1))) + '_index_add']
        rt_info1.append(args[1])
        rt_info1.append('i')
        rt_info1.append('0')
        rt_info1.append(pre1 + 'rr' + str(self.module_info[3]-1-int(res.group(1)))  + '_add')
        if self.d:
            rt_info0.append('del')
            rt_info1.append('del')
        return [rt_info0, rt_info1]

    def parse_KS(self, res):
        args = self.parse_primitive_arg(res.group(2), 3)

        pre0 = 'SwitchIngress.ks' + res.group(1) + '.'
        rt_info0 = [pre0 + 'tb_key_selection']
        rt_info0.append(args[2])
        rt_info0.append(pre0 + re.sub(r'(\.)', '', args[0]) + '_temp' + args[1])

        if self.d:
            rt_info0.append('del')

        return [rt_info0]

    def parse_HM(self, res):
        args = self.parse_primitive_arg(res.group(2), 3)

        pre0 = 'SwitchIngress.hm' + res.group(1) + '.'
        rt_info0 = [pre0 + 'tb_header_modifier']

        if re.match(r'\d+', args[1]):
            rt_info0.append(args[2])
            rt_info0.append(pre0 + re.sub(r'(\.)', '', args[0]) + '_temp' + args[1])
        else:
            rt_info0.append(args[2])
            rt_info0.append(pre0 + re.sub(r'(\.)', '', args[0]) + '_' + re.sub(r'(\.)', '', args[1]))

        if self.d:
            rt_info0.append('del')

        return [rt_info0]

    def parse_AR(self, res):
        def parse_register_action(res):
            args = self.parse_primitive_arg(res.group(3), 2)

            pre0 = 'SwitchIngress.ps.'
            rt_info0 = [pre0 + 'tb_rr' + res.group(1) + '_parameter_setting0']
            rt_info0.append(args[1])
            rt_info0.append('p')
            if re.search(r'(add|and|read)', res.group(2)):
                rt_info0.append('0')
            else:
                rt_info0.append('1')
            rt_info0.append(pre0 + 'set_' + res.group(1) + '_0')

            if(re.match(r'\d+', args[0])):
                rt_info1 = [pre0 + 'tb_rr' + res.group(1) + '_parameter_setting1']
                rt_info1.append(args[1])
                rt_info1.append('p')
                rt_info1.append(args[0])
                rt_info1.append(pre0 + 'set_' + res.group(1) + '_1')
            else:
                rt_info1 = [pre0 + 'tb_rr' + res.group(1) + '_parameter_setting1']
                rt_info1.append(args[1])
                rt_info1.append(pre0 + 'set_' + res.group(1) + '_' + re.sub(r'(\.)', '', args[0]))

            pre1 = 'SwitchIngress.rr.'
            rt_info2 = [pre1 + 'tb_rr' + res.group(1) + '_reg']
            rt_info2.append(args[1])
            if re.search(r'(add|sub)', res.group(2)):
                rt_info2.append(pre1 + 'rr' + res.group(1) + '_reg_op0')
            if re.search(r'(and|or)', res.group(2)):
                rt_info2.append(pre1 + 'rr' + res.group(1) + '_reg_op1')
            if re.search(r'(read|write)', res.group(2)):
                rt_info2.append(pre1 + 'rr' + res.group(1) + '_reg_op2')
            if re.search(r'max', res.group(2)):
                rt_info2.append(pre1 + 'rr' + res.group(1) + '_reg_op3')

            if self.d:
                rt_info0.append('del')
                rt_info1.append('del')
                rt_info2.append('del')

            return [rt_info0, rt_info1, rt_info2]


        def parse_uanry(res):
            args = self.parse_primitive_arg(res.group(3), 2)

            pre0 = 'SwitchIngress.rr.'
            rt_info0 = [pre0 + 'tb_rr' + res.group(1)]
            rt_info0.append(args[1])
            rt_info0.append(res.group(2) + '_' + res.group(1) + '_' + args[0])

            if self.d:
                rt_info0.append('del')

            return [rt_info0]
        
        def parse_uanry_i(res):
            args = self.parse_primitive_arg(res.group(3), 3)

            pre0 = 'SwitchIngress.rr.'
            rt_info0 = [pre0 + 'tb_rr' + res.group(1)]
            rt_info0.append(args[2])
            rt_info0.append(re.sub("i", "", res.group(2)) + '_' + res.group(1) + '_' + args[0] + '_i')
            rt_info0.append("i")
            rt_info0.append(args[1])

            if self.d:
                rt_info0.append('del')

            return [rt_info0]

        def parse_binary(res):
            args = self.parse_primitive_arg(res.group(3), 2)

            pre0 = 'SwitchIngress.rr.'
            rt_info0 = [pre0 + 'tb_rr' + res.group(1)]
            rt_info0.append(args[2])
            rt_info0.append(res.group(2) + '_' + res.group(1) + '_' + args[0] + '_' + args[1])

            if self.d:
                rt_info0.append('del')
                
            return [rt_info0]

        if re.match(r'(register_add|register_sub|register_and|register_or|register_read|register_write|register_max)', res.group(2)):
            return parse_register_action(res)
        elif re.match(r'(addi|andi|ori|xori)', res.group(2)):
            return parse_uanry_i(res)
        elif re.match(r'(add|sub|mul|and|or|xor)', res.group(2)):
            return parse_binary(res)
        elif re.match(r'(ass|not)', res.group(2)):
            return parse_uanry(res)
        else:
            self.error('parse error')
    
    def parse_rec(self, res):
        args = self.parse_primitive_arg(res.group(1), 2)

        rt_info0 = ['SwitchIngress.tb_recirculate']
        rt_info0.append(args[0])
        if args[1] == '0':
            rt_info0.append('SwitchIngress.first_recirculate')
        if args[1] == '1':
            rt_info0.append('SwitchIngress.last_recirculate')
        if args[1] == '2':
            rt_info0.append('SwitchIngress.recirculate')

        if self.d:
            rt_info0.append('del')

        return [rt_info0]

    def parse_line(self):
        attributes = []
        self.line_num = 0
        self.module_info = [1,3,2,4,2]
        line = "line"
        '''
        res = re.match(r'module_info\((.*)\)\s*', line)
        if not res:
            #self.error('no module_info primitive', self.line_num)
            self.module_info = [1,3,2,4,2]
        else: 
            args = self.parse_primitive_arg(res.group(1), 5)
            for i in range(5):
                self.module_info[i] = int(args[i])
        '''
        while line:
            line = self.f.readline()
            if line is None:
                break
            self.line_num = self.line_num + 1
            self.d = False
            if re.match(r'del\((.*)\)\s*', line):
                res = re.match(r'del\((.*)\)\s*', line)
                line = res.group(1)
                self.d = True
            if re.match(r'FS(\d)\.filter_setting\((.*)\)\s*', line):
                res = re.match(r'FS(\d)\.filter_setting\((.*)\)\s*', line)
                attributes = attributes + self.parse_FS(res)
            elif re.match(r'IS(\d)\.index_setting_hash\((.*)\)\s*', line):
                res = re.match(r'IS(\d)\.index_setting_hash\((.*)\)\s*', line)
                attributes = attributes + self.parse_IS(res)
            elif re.match(r'IS(\d)\.index_setting_manually\((.*)\)\s*', line):
                res = re.match(r'IS(\d)\.index_setting_manually\((.*)\)\s*', line)
                attributes = attributes + self.parse_ISM(res)
            elif re.match(r'KS(\d)\.key_selection\((.*)\)\s*', line):
                res = re.match(r'KS(\d)\.key_selection\((.*)\)\s*', line)
                attributes = attributes + self.parse_KS(res)
            elif re.match(r'HM(\d)\.header_modifier\((.*)\)\s*', line):
                res = re.match(r'HM(\d)\.header_modifier\((.*)\)\s*', line)
                attributes = attributes + self.parse_HM(res)
            elif re.match(r'AR(\d)\.(%s)\((.*)\)\s*' % self.actions, line):
                res = re.match(r'AR(\d)\.(%s)\((.*)\)\s*' % self.actions, line)
                attributes = attributes + self.parse_AR(res)
            elif re.match(r'rec\((.*)\)', line):
                res = re.match(r'rec\((.*)\)', line)
                attributes = attributes + self.parse_rec(res)
            elif re.match(r'//', line):
                continue
            elif re.match(r'\n', line):
                continue
            else:
                print('line' + str(self.line_num) + ':\tskip unknown line:\t' + line)
                continue
        if self.p:
            for i in attributes:
                print(i)
        return attributes


    
    






