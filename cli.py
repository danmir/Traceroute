import argparse
import sys
import os
from or_trace import Trace


class CLI():

    def __init__(self):
        self.firewall = 1

    def console_mode(self):
        parser = argparse.ArgumentParser(
            description='Trace route to specified host')

        parser.add_argument(
            '--dest_host', '-d', required=True, help="Destination host Ex:'e1.ru'")
        parser.add_argument(
            '--timeout', '-t', required=True, type=int, help="Timeout for recv info in seconds Ex:'1'")

        return parser

    def run_trace(self, p_namespace):
        trace = Trace(p_namespace.dest_host, p_namespace.timeout, 1)
        trace_gen = trace.run_trace()
        for server in trace_gen:
            print("%d\t%s Delay: %s" %
                  (server["ttl"], server["host_info"], server["delay"]))
            print("\tCountry code: %s" % (server["country_code"]))
            print("\tAS: %s" % (server["as"]))

    def nt_system(self):
        if self.firewall == 1:
            os.system('netsh advfirewall set  allprofiles state off')
            self.firewall = 0
        else:
            os.system('netsh advfirewall set  allprofiles state on')


if __name__ == '__main__':
    i_interface = CLI()
    parser = i_interface.console_mode()
    namespace = parser.parse_args(sys.argv[1:])
    if os.name == "nt":
        i_interface.nt_system()
        i_interface.run_trace(namespace)
        i_interface.nt_system()
    else:
        i_interface.run_trace(namespace)
