# -*- coding:UTF-8 -*-
import sys
sys.path.append("/usr/local/python3/lib/python3.5/site-packages")
import os
import logging
import time
import traceback
import json
import cmd
import argparse
from scapy.all import Ether, IP, UDP, sendp
import ipaddress
import prettytable as pt

from rpp import RPP
from runtime import bfrt_runtime
from entry_dumper import entry_dumper

class ArgParser(argparse.ArgumentParser):

    def __init__(self, *args, **kwargs):
        super(ArgParser, self).__init__(*args, **kwargs)

        self.error_message = ''

    def error(self, message):
        self.error_message = message

    def parse_args(self, *args, **kwargs):
        # catch SystemExit exception to prevent closing the application
        result = None
        try:
            result = super(ArgParser, self).parse_args(*args, **kwargs)
        except SystemExit:
            pass
        return result

class P4R2Controller(cmd.Cmd):
    intro = """
    P4R2 controller start!!
    """
    prompt = 'P4R2> '

    def __init__(self, config_file = 'config.json'):
        cmd.Cmd.__init__(self)
        try:
            #self.config = json.load(open(config_file, 'r'))
            self.runtime = bfrt_runtime(0, 'p4r2')
            self.entry_dumper = entry_dumper(self.runtime)
            self.rpp = RPP()
        except Exception as e:
            print(traceback.format_exc())
            #print(f"{e} when loading configure file.")
            exit(1)

    def emptyline(self):
        pass
    
    def do_exit(self, line):
        print("")
        exit(0)

    def do_parse_primitive(self, arg):
        """ parse a primitive file
        Args:
            "-f", "--file" : primitive file path
            "-p", "--print"    : print details of the paresing information
        Exceptions:
            parser error
        """

        parser = ArgParser()
        parser.add_argument("-f", "--file", dest="file", type=str, required=True, help="e.g., ./primitives.txt")
        parser.add_argument("-p", "--print", dest="p", type=int, required=True, default=0, help="0 or 1,  0 means no detail is printed, 1 is the opposite")

        try:
            args = parser.parse_args(arg.split())
            if parser.error_message or args is None:
                print(parser.error_message)
                return

            time_start = time.time()
            parse_info = self.rpp.start(args.file, args.p)
            time_parse = time.time()
            self.entry_dumper.dump(parse_info)
            time_end = time.time()

            print("\nprimitive parsing success")
            print("parsing time:\t" + str((time_parse - time_start)*1000) + "ms")
            print("dumping time:\t" + str((time_end - time_parse)*1000) + "ms")
            print("total time:\t" + str((time_end - time_start)*1000) + "ms\n")

        except Exception as e:
            print(traceback.format_exc())
            print(e)
            return None
        
    def do_task_deployment_test(self, arg):


        tasks = [
            "../primitives_new/basic_forward.txt",
            "../primitives_new/basic_tunnel.txt",
            "../primitives_new/netcache.txt",
            "../primitives_new/basic_forward_delete.txt",
            "../primitives_new/basic_tunnel_delete.txt",
            "../primitives_new/load_balance.txt",
            "../primitives_new/cms.txt",
            "../primitives_new/netcache_modification.txt"
        ]

        try:

            parse_info = self.rpp.start(tasks[0], 1)
            self.entry_dumper.dump(parse_info)

            time.sleep(4)

            self.entry_dumper.clear_all()
            parse_info = self.rpp.start(tasks[0], 1)
            self.entry_dumper.dump(parse_info)

            time.sleep(4)
            self.entry_dumper.clear_all()

        except Exception as e:
            print(traceback.format_exc())
            print(e)
            return None

    def do_add_froward(self, arg):
        """ parse a primitive file
        Args:
            "-ip", "--ingress_port" : ingress port number
            "-ep", "--egress_port"    : egress port number
        Returns:
            None
        Exceptions:
            parser error
        """

        parser = ArgParser()
        parser.add_argument("-ip", "--ingress_port", dest="ingress_port", type=int, required=True, default="", help="a int number")
        parser.add_argument("-ep", "--egress_port", dest="egress_port", type=int, required=True, help="a int number")

        try:
            args = parser.parse_args(arg.split())
            if parser.error_message or args is None:
                print(parser.error_message)
                return

            self.runtime.entry_add("SwitchIngress.tb_forward", [["ig_intr_md.ingress_port", int(args.ingress_port), "exact"]], [[["port", int(args.egress_port)]], "SwitchIngress.forward"])

            return None

        except Exception as e:
            print(traceback.format_exc())
            print(e)
            return None

    def do_del_froward(self, arg):
        """ parse a primitive file
        Args:
            "-ip", "--ingress_port" : ingress port number
        Returns:
            None
        Exceptions:
            parser error
        """

        parser = ArgParser()
        parser.add_argument("-ip", "--ingress_port", dest="ingress_port", type=int, required=True, default="", help="a int number")

        try:
            args = parser.parse_args(arg.split())
            if parser.error_message or args is None:
                print(parser.error_message)
                return

            self.runtime.entry_del("SwitchIngress.tb_forward", [["ig_intr_md.ingress_port", int(args.ingress_port), "exact"]])

            return None

        except Exception as e:
            print(traceback.format_exc())
            print(e)
            return None
    
    def do_clear_all(self, arg):
        self.entry_dumper.clear_all()
        print("clear done")


if __name__ == "__main__":
    P4R2Controller().cmdloop()