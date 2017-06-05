# -*- coding: utf-8 -*-
from __future__ import print_function

from six.moves import socketserver
import syslogmp

class SyslogUDPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data, socket = self.request

        iptables_log = parse_syslog(data)


def parse_syslog(data):
    parsed_data = syslogmp.parse(data)
    message = parsed_data.message
    if not message.startswith('kernel: ['):
        # Not a kernel message
        return None

    parts = message.strip().split(' ')
    # parts[0] is 'kernel: '
    # parts[1] is timestamp from boot
    # parts[2] is the log-prefix
    # parts[3..] is either KEY=VALUE or just KEY
    if not parts[3].startswith('IN='):
        # not an iptables message
        return None

    fields = {k: v for k, _, v in (field.partition('=') for field in parts[3:])}
    fields['prefix'] = parts[2]
    return fields


def lookup_container_by_ip(ip_address):

def run_server():
    server = socketserver.UDPServer(('0.0.0.0', 1226), SyslogUDPHandler)
    server.serve_forever()


if __name__ == '__main__':
    run_server()
