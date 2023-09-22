import re


class RPC():
    file_path = None
    f = None
    p = 0
    module_info = [0, 0, 0, 0, 0]

    actions = 'ass|add|del|mul|and|or|not|register_add|register_del|register_and|register_or|register_read|register_write'

    def error(self, s, n=None):
        es = 'error:\t'
        if n:
            es = es + 'line' + str(n) + '\t'
        es = es + s
        print(es)
        exit()

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

        pre0 = 'SwitchIngress.fs' + res.group(1) + '.'
        rt_info0 = [pre0 + 'tb_filter_setting']
        rt_info0.append((len(args)-1)/3)
        for i in range(len(args)-1):
            rt_info0.append(args[i])
        rt_info0.append('filterID')
        rt_info0.append(args[-1])
        rt_info0.append(pre0 + 'set_filter')
        if self.d:
            rt_info0.append('del')
        return [rt_info0]

    def parse_IS(self, res):
        args = self.parse_primitive_arg(res.group(2), 5)

        pre0 = 'SwitchIngress.hi' + res.group(1) + '.'
        rt_info0 = [pre0 + 'tb_hashed_index_setting']
        rt_info0.append(args[4])
        rt_info0.append(pre0 + 'set_index_' + re.sub(r'(\.)', '', args[0]))

        pre1 = 'SwitchIngress.at' + res.group(1) + '.'
        rt_info1 = [pre1 + 'tb_index_shift']
        rt_info1.append(args[4])
        rt_info1.append(pre1 + 'rr' + args[3] + '_shift_' + args[1])

        rt_info2 = [pre1 + 'tb_index_add']
        rt_info2.append(args[4])
        rt_info2.append('i')
        rt_info2.append(args[2])
        rt_info2.append(pre1 + 'rr' + args[3] + '_add')

        if self.d:
            rt_info0.append('del')
            rt_info1.append('del')
            rt_info2.append('del')
        if int(args[1]) == 0:
            return [rt_info0, rt_info2]
        return [rt_info0, rt_info1, rt_info2]
    
    def parse_ISM(self, res):
        args = self.parse_primitive_arg(res.group(2), 2)

        pre0 = 'SwitchIngress.hi' + res.group(1) + '.'
        rt_info0 = [pre0 + 'tb_hashed_index_setting']
        rt_info0.append(args[1])
        rt_info0.append('index')
        rt_info0.append(args[0])
        rt_info0.append(pre0 + 'set_index_manually')
        if self.d:
            rt_info0.append('del')
        return [rt_info0]

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
        rt_info0.append(args[2])
        rt_info0.append(pre0 + re.sub(r'(\.)', '', args[0]) + '_temp' + args[1])

        if self.d:
            rt_info0.append('del')

        return [rt_info0]

    def parse_AR(self, res):
        def parse_register_action(res):
            args = self.parse_primitive_arg(res.group(3), 2)

            pre0 = 'SwitchIngress.ps0.'
            rt_info0 = [pre0 + 'tb_parameter_setting0']
            rt_info1 = [pre0 + 'tb_parameter_setting1']
            rt_info0.append(args[1])
            rt_info1.append(args[1])
            rt_info0.append('p')
            rt_info1.append('p')
            if re.match(r'(add|and|read)', res.group(2)):
                rt_info0.append('0')
            else:
                rt_info0.append('1')
            rt_info1.append(args[0])
            rt_info0.append(pre0 + 'set_' + res.group(1) + '_0')
            rt_info1.append(pre0 + 'set_' + res.group(1) + '_1')

            pre1 = 'SwitchIngress.rr.'
            rt_info2 = [pre1 + 'tb_rr' + res.group(1)]
            rt_info2.append(args[1])
            if re.search(r'(add|del)', res.group(2)):
                rt_info2.append(pre1 + 'rr' + res.group(1) + '_reg_op0')
            if re.search(r'(and|or)', res.group(2)):
                rt_info2.append(pre1 + 'rr' + res.group(1) + '_reg_op1')
            if re.search(r'(read|write)', res.group(2)):
                rt_info2.append(pre1 + 'rr' + res.group(1) + '_reg_op2')

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

        def parse_binary(res):
            args = self.parse_primitive_arg(res.group(3), 2)

            pre0 = 'SwitchIngress.rr.'
            rt_info0 = [pre0 + 'tb_rr' + res.group(1)]
            rt_info0.append(args[0])
            rt_info0.append(res.group(2) + '_' + res.group(1) + '_' + args[0] + '_' + args[1])

            if self.d:
                rt_info0.append('del')
                
            return [rt_info0]

        if re.match(r'(register_add|register_del|register_and|register_or|register_read|register_write)', res.group(2)):
            return parse_register_action(res)
        elif re.match(r'(add|del|mul|and|or)', res.group(2)):
            return parse_binary(res)
        elif re.match(r'(ass|not)', res.group(2)):
            return parse_uanry(res)
        else:
            self.error('parse error')

    def parse_line(self):
        attributes = []
        self.line_num = 1
        line = self.f.readline()
        res = re.match(r'module_info\((.*)\)\s*', line)
        if not res:
            self.error('no module_info primitive', self.line_num)
        args = self.parse_primitive_arg(res.group(1), 5)
        for i in range(5):
            self.module_info[i] = [int(args[i])]
        while line:
            line = self.f.readline()
            self.line_num = self.line_num + 1
            self.d = False
            if re.match(r'del\((.*)\)\s*', line):
                res = re.match(r'del\((.*)\)\s*', line)
                line = res.group(1)
                self.d = True
            if re.match(r'FS(\d)\.filter_setting\((.*)\)\s*', line):
                res = re.match(r'FS(\d)\.filter_setting\((.*)\)\s*', line)
                attributes = attributes + self.parse_FS(res)
            elif re.match(r'IS(\d)\.index_setting\((.*)\)\s*', line):
                res = re.match(r'IS(\d)\.index_setting\((.*)\)\s*', line)
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
            else:
                print('line' + str(self.line_num) + ':\tskip unknown line:\t' + line)
                continue
        if self.p:
            for i in attributes:
                print(i)
        return attributes


    
    






