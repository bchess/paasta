# -*- coding: utf-8 -*-
from __future__ import print_function

import argparse
import logging
import sys

from six.moves import socketserver
import syslogmp

from paasta_tools.firewall import services_running_here


log = logging.getLogger(__name__)


class SyslogUDPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data, socket = self.request

        syslog_to_scribe(data)


def syslog_to_scribe(data):
    iptables_log = parse_syslog(data)
    service, instance = lookup_service_instance_by_ip(iptables_log['SRC'])
    if service is None:
        return

    ScribeLogWriter().log(
        service,
        iptables_log['message'],
        'security',
        'warning',
        #cluster=TODO,
        instance=instance,
    )


def parse_syslog(data):
    parsed_data = syslogmp.parse(data)
    full_message = parsed_data.message
    if not full_message.startswith('kernel: ['):
        # Not a kernel message
        return None

    close_bracket = full_message.find(']')
    if close_bracket == -1:
        return None

    iptables_message = full_message[close_bracket:].strip()
    parts = iptables_message.split(' ')
    # parts[0] is the log-prefix
    # parts[1..] is either KEY=VALUE or just KEY
    if not parts[1].startswith('IN='):
        # not an iptables message
        return None

    fields = {k: v for k, _, v in (field.partition('=') for field in parts[1:])}
    fields['prefix'] = parts[0]
    fields['message'] = iptables_message
    return fields


def lookup_service_instance_by_ip(ip_lookup):
    for service, instance, mac, ip in services_running_here():
        if ip == ip_lookup:
            return (service, instance)
    log.info('Unable to find container for ip {}'.format(ip_lookup))
    return (None, None)


def run_server(listen_host, listen_port):
    logging.basicConfig(level=logging.DEBUG)
    server = socketserver.UDPServer((listen_host, listen_port), SyslogUDPHandler)
    server.serve_forever()


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description='Adapts iptables syslog messages into scribe')
    parser.add_argument('-v', '--verbose', action='store_true',
                        dest="verbose", default=False)
    parser.add_argument('-l', '--listen-host', help='Default %(default)s', default='0.0.0.0')
    parser.add_argument('-p', '--listen-port', type=int, help='Default %(default)s', default=1516)
    args = parser.parse_args(argv)
    return args


def setup_logging(verbose):
    if verbose:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.WARNING)


def main(argv=None):
    args = parse_args(argv)
    setup_logging(args.verbose)
    run_server(args.listen_host, args.listen_port)

if __name__ == '__main__':
    main()
