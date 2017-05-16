# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import print_function
from __future__ import unicode_literals

import argparse
import logging
import os.path
import time
from collections import defaultdict

from inotify.adapters import Inotify
from inotify.constants import IN_MODIFY
from inotify.constants import IN_MOVED_TO

from paasta_tools.marathon_tools import load_marathon_service_config
from paasta_tools.marathon_tools import marathon_services_running_here
from paasta_tools.utils import DEFAULT_SOA_DIR
from paasta_tools.utils import load_system_paasta_config

log = logging.getLogger(__name__)

UPDATE_SECS = 5
SYNAPSE_SERVICE_DIR = b'/var/run/synapse/services'


def smartstack_dependencies_of_running_firewalled_services(soa_dir=DEFAULT_SOA_DIR):
    dependencies_to_services = defaultdict(list)

    cluster = load_system_paasta_config().get_cluster()
    for service, instance, port in marathon_services_running_here():  # TODO: + chronos
        config = load_marathon_service_config(service, instance, cluster, load_deployments=False, soa_dir=soa_dir)

        outbound_firewall = config.get_outbound_firewall()
        if not outbound_firewall:
            continue

        dependencies = config.get_dependencies()

        smartstack_dependencies = [d['smartstack'] for d in dependencies if d.get('smartstack')]
        for smartstack_dependency in smartstack_dependencies:
            # TODO: filter down to only services that have no proxy_port
            dependencies_to_services[smartstack_dependency].append((service, instance))

    return dependencies_to_services


def parse_args(argv):
    parser = argparse.ArgumentParser(description='Monitor synapse changes and update service firewall rules')
    parser.add_argument('--synapse-service-dir', dest="synapse_service_dir",
                        default=SYNAPSE_SERVICE_DIR,
                        help="Path to synapse service dir (default %(default)s)")
    parser.add_argument('-d', '--soa-dir', dest="soa_dir", metavar="soa_dir",
                        default=DEFAULT_SOA_DIR,
                        help="define a different soa config directory (default %(default)s)")
    parser.add_argument('-u', '--update-secs', dest="update_secs",
                        default=UPDATE_SECS, type=int,
                        help="Poll for new containers every N secs (default %(default)s)")
    parser.add_argument('-v', '--verbose', dest='verbose', action='store_true')

    args = parser.parse_args(argv)
    return args


class FirewallUpdate(object):
    def __init__(self, argv=None):
        self.args = self.parse_args(argv)
        self.setup_logging()

        self.inotify = Inotify(block_duration_s=1)  # event_gen blocks for 1 second
        self.inotify.add_watch(self.args.synapse_service_dir, IN_MOVED_TO | IN_MODIFY)

        self.services_by_dependencies = None
        self.services_by_dependencies_time = 0
        self.maybe_check_new_services()

    def setup_logging(self):
        if self.args.verbose:
            logging.basicConfig(level=logging.DEBUG)
        else:
            logging.basicConfig(level=logging.WARNING)

    def maybe_check_new_services(self):
        if self.services_by_dependencies_time + self.args.update_secs > time.time():
            return
        self.services_by_dependencies = smartstack_dependencies_of_running_firewalled_services(
            soa_dir=self.args.soa_dir)
        self.services_by_dependencies_time = time.time()
        log.debug(self.services_by_dependencies)

    def run(self):
        # Main loop waiting on inotify file events
        for event in self.inotify.event_gen():  # blocks for only up to 1 second at a time
            self.maybe_check_new_services()

            if event is None:
                continue

            self.process_inotify_event(event)

    def process_inotify_event(self, event):
        filename = event[3]
        service_instance, suffix = os.path.splitext(filename)
        if suffix != '.json':
            return

        services_to_update = self.services_by_dependencies.get(service_instance, ())
        for service_to_update in services_to_update:
            log.debug('Update ', service_to_update)
            pass  # TODO: iptables added and removed here! :o)


def main(argv=None):
    FirewallUpdate(argv).run()
