import socket
import struct
import random
import time
import select
import sys
import re


class CheckWhois():

    def __init__(self, dest_ip, timeout):
        super(CheckWhois, self).__init__()
        self.dest_ip = dest_ip
        self.timeout = timeout

    def _perform_whois(self, server, query):
        """
        Method that goes on a specified whois @param: server
        and asks about @param: query
        Returns info in utf-8
        """
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.connect((server, 43))
        except Exception as msg:
            print("Smth wrong with whois server {}".format(msg))

        s.send(bytes(query, "utf-8") + b'\r\n')

        # receive reply
        msg = b''
        while 1:
            # Check timeout
            started_select = time.time()
            ready = select.select([s], [], [], self.timeout)
            how_long_in_select = time.time() - started_select
            if ready[0] == []:  # Timeout
                return "Timeout"
            data = s.recv(4096)
            msg += data
            if not data:
                break

        return msg.decode("utf-8")

    def _get_whois_data(self, domain):
        """
        This method asks 'whois.iana.org' about @param: domain then
        goes to a region whois to check detailed info
        """
        whois = 'whois.iana.org'
        msg = self._perform_whois(whois, domain)
        # Now search the reply for a whois server
        # And check if time is out
        lines = msg.splitlines()
        for line in lines:
            if ':' in line:
                words = line.split(':')
                if 'whois' in words[0]:
                    whois = words[1].strip()
                    break

        # Now contact the final whois server if no timeout
        if msg != "Timeout":
            msg = self._perform_whois(whois, domain)
            # Return the reply
            return msg
        else:
            return "Timeout"

    def _get_as_num(self, msg):
        """
        Parce msg from whois server
        Return oridinAS and country code
        """
        country_m = re.search("country:(.*)", msg, flags=re.IGNORECASE)
        try:
            country_code = country_m.group(1).strip()
        except AttributeError:
            country_code = None

        originAS_m = re.search("OriginAS:(.*)", msg, flags=re.IGNORECASE)
        try:
            originAS = originAS_m.group(1).strip()
        except AttributeError:
            originAS_m = re.search("Origin:(.*)", msg, flags=re.IGNORECASE)
            try:
                originAS = originAS_m.group(1).strip()
            except AttributeError:
                originAS = None

        return country_code, originAS

    def get_whois_info(self):
        """
        Perform whois query about asked ip
        Return msg, country_code, originAS
        If timeout - "Timeout", None, None
        """
        msg = self._get_whois_data(self.dest_ip)
        country_code, originAS = self._get_as_num(msg)
        if country_code is None:
            country_code = "Not found"
        if originAS is None:
            originAS = "Not found"
        return msg, country_code, originAS


def main():
    """
    For tests
    """
    ip = sys.argv[1]
    dest_ip = socket.gethostbyname(ip)

    timeout = 1
    c = CheckWhois(dest_ip, timeout)
    msg, country_code, originAS = c.check()
    print(msg)
    print(country_code, originAS)

if __name__ == '__main__':
    main()
