# -*- coding: utf-8 -*-
"""
"""
from __future__ import absolute_import
from __future__ import unicode_literals

from service_configuration_lib import read_extra_service_information

from paasta_tools.utils import DEFAULT_SOA_DIR
from paasta_tools.utils import time_cache


@time_cache(ttl=5)
def get_dependency_config(service, soa_dir=DEFAULT_SOA_DIR):
    # TODO: make dependencies a first-class citizen in service_configuration_lib
    return read_extra_service_information(service, 'dependencies', soa_dir)


def get_dependencies_of_service(service_config, soa_dir=DEFAULT_SOA_DIR):
    dependency_reference = service_config.get_dependency_reference()
    if not dependency_reference:
        return None

    dependency_config = get_dependency_config(service_config.service, soa_dir=soa_dir)
    return dependency_config.get(dependency_reference)
