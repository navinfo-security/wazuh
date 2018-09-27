#!/usr/bin/env python

# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from wazuh import common
from wazuh.exception import WazuhException
from wazuh.agent import Agent
from wazuh.utils import plain_dict_to_nested_dict, get_fields_to_nest
from operator import itemgetter
import functools


def get_item_agent(agent_id, offset, limit, select, search, sort, filters, valid_select_fields, allowed_sort_fields, table, nested=True, array=False):
    Agent(agent_id).get_basic_information()

    if select:
        select_fields = set(select['fields'])
        if not select_fields.issubset(set(valid_select_fields.keys())):
            incorrect_fields = map(lambda x: str(x), select_fields - set(valid_select_fields.keys()))
            raise WazuhException(1724, "Allowed select fields: {0}. Fields {1}". \
                                 format(', '.join(valid_select_fields.keys()), ','.join(incorrect_fields)))
    else:
        select_fields = valid_select_fields.keys()

    if search:
        search['fields'] = valid_select_fields.keys()

    # Sorting
    if sort and sort['fields']:
        # Check if every element in sort['fields'] is in allowed_sort_fields.
        if not set(sort['fields']).issubset(set(allowed_sort_fields.keys())):
            raise WazuhException(1403, 'Allowed sort fields: {0}. Fields: {1}'.format(
                ', '.join(allowed_sort_fields.keys()), ','.join(sort['fields'])))

        sort['fields'] = [valid_select_fields[x] for x in sort['fields']]

    response, total = Agent(agent_id)._load_info_from_agent_db(table=table, offset=offset, limit=limit,
                                                               select={valid_select_fields[x] for x in select_fields},
                                                               count=True, sort=sort, search=search, filters=filters)

    if array:
        return_data = response if not nested else list(map(lambda x: plain_dict_to_nested_dict(x), response))
    elif not response:
        return_data = {}
    else:
        return_data = response[0] if not nested else plain_dict_to_nested_dict(response[0])

    return {'items': return_data, 'totalItems': total} if array else return_data


def get_os_agent(agent_id, offset=0, limit=common.database_limit, select={}, search={}, sort={}, filters={}, nested=True):
    """
    Get info about an agent's OS
    """
    agent_obj = Agent(agent_id)
    agent_obj.get_basic_information()

    # The osinfo fields in database are different in Windows and Linux
    os_name = agent_obj.get_agent_attr('os_name')
    windows_fields = {'hostname': 'hostname', 'os_version': 'os_version', 'os_name': 'os_name',
                      'architecture': 'architecture', 'os_major': 'os_major', 'os_minor': 'os_minor',
                      'os_build': 'os_build',
                      'version': 'version', 'scan_time': 'scan_time', 'scan_id': 'scan_id'}
    linux_fields = windows_fields | {'os_codename': 'os_codename', 'os_platform': 'os_platform', 'sysname': 'sysname',
                                     'release': 'release'}

    valid_select_fields = windows_fields if 'Windows' in os_name else linux_fields

    allowed_sort_fields = {'os_name', 'hostname', 'architecture'}

    return get_item_agent(agent_id=agent_id, offset=offset, limit=limit, select=select,
                         search=search, sort=sort, filters=filters, allowed_sort_fields=allowed_sort_fields,
                         valid_select_fields=valid_select_fields, table='sys_osinfo', nested=nested)


def get_hardware_agent(agent_id, offset=0, limit=common.database_limit, select={}, search={}, sort={}, filters={}, nested=True):
    """
    Get info about an agent's OS
    """
    valid_select_fields = {'board_serial': 'board_serial', 'cpu_name': 'cpu_name', 'cpu_cores': 'cpu_cores', 'cpu_mhz': 'cpu_mhz',
                           'ram_total': 'ram_total', 'ram_free': 'ram_free', 'ram_usage': 'ram_usage', 'scan_id': 'scan_id',
                           'scan_time': 'scan_time'}

    return get_item_agent(agent_id=agent_id, offset=offset, limit=limit, select=select,
                         search=search, sort=sort, filters=filters, allowed_sort_fields=valid_select_fields,
                         valid_select_fields=valid_select_fields, table='sys_hwinfo', nested=nested)


def get_packages_agent(agent_id, offset=0, limit=common.database_limit, select={}, search={}, sort={}, filters={}, nested=True):
    """
    Get info about an agent's programs
    """
    valid_select_fields = {'scan_id': 'scan_id', 'scan_time': 'scan_time', 'format': 'format', 'name': 'name', 'priority': 'priority',
                           'section': 'section', 'size': 'size', 'vendor': 'vendor', 'install_time': 'install_time',
                           'version': 'version', 'architecture': 'architecture', 'multiarch': 'multiarch', 'source': 'source',
                           'description': 'description', 'location': 'location'}

    return get_item_agent(agent_id=agent_id, offset=offset, limit=limit, select=select,
                         search=search, sort=sort, filters=filters, allowed_sort_fields=valid_select_fields,
                         valid_select_fields=valid_select_fields, table='sys_programs', array=True, nested=nested)


def get_processes_agent(agent_id, offset=0, limit=common.database_limit, select={}, search={}, sort={}, filters={}, nested=True):
    """
    Get info about an agent's processes
    """
    valid_select_fields = {'scan_id': 'scan_id', 'scan_time': 'scan_time', 'pid': 'pid', 'name': 'name',
                           'state': 'state', 'ppid': 'ppid', 'utime': 'utime', 'stime': 'stime', 'cmd': 'cmd',
                           'argvs': 'argvs', 'euser': 'euser', 'ruser': 'ruser', 'suser': 'suser', 'egroup': 'egroup',
                           'rgroup': 'rgroup', 'sgroup': 'sgroup', 'fgroup': 'fgroup', 'priority': 'priority',
                           'nice': 'nice', 'size': 'size', 'vm_size': 'vm_size', 'resident': 'resident', 'share': 'share',
                           'start_time': 'start_time', 'pgrp': 'pgrp', 'session': 'session', 'nlwp': 'nlwp', 'tgid': 'tgid',
                           'tty': 'tty', 'processor': 'processor'}

    return get_item_agent(agent_id=agent_id, offset=offset, limit=limit, select=select,
                         search=search, sort=sort, filters=filters, allowed_sort_fields=valid_select_fields,
                         valid_select_fields=valid_select_fields, table='sys_processes', array=True, nested=nested)


def get_ports_agent(agent_id, offset=0, limit=common.database_limit, select={}, search={}, sort={}, filters={}, nested=True):
    """
    Get info about an agent's ports
    """
    valid_select_fields = {'scan_id': 'scan_id', 'scan_time': 'scan_time', 'protocol': 'protocol', 'local_ip': 'local_ip',
                           'local_port': 'local_port', 'remote_ip': 'remote_ip', 'remote_port': 'remote_port',
                           'tx_queue': 'tx_queue', 'rx_queue': 'rx_queue', 'inode': 'inode', 'state': 'state', 'pid': 'pid',
                           'process': 'process'}

    return get_item_agent(agent_id=agent_id, offset=offset, limit=limit, select=select,
                          search=search, sort=sort, filters=filters, allowed_sort_fields=valid_select_fields,
                          valid_select_fields=valid_select_fields, table='sys_ports', array=True, nested=nested)


def __get_netaddr_fields(exclude_fields=set()):
    fields = {'scan_id': 'scan_id', 'proto': 'proto', 'address': 'address', 'netmask': 'netmask', 'broadcast': 'broadcast'}
    return fields if not exclude_fields else dict(filter(lambda x: x[0] not in exclude_fields, fields.items()))


def get_netaddr_agent(agent_id, offset=0, limit=common.database_limit, select={}, search={}, sort={}, filters={}, nested=True):
    """
    Get info about an agent's network address
    """
    valid_select_fields = __get_netaddr_fields()

    return get_item_agent(agent_id=agent_id, offset=offset, limit=limit, select=select,
                          search=search, sort=sort, filters=filters, allowed_sort_fields=valid_select_fields,
                          valid_select_fields=valid_select_fields, table='sys_netaddr', array=True, nested=nested)


def __get_netproto_fields(exclude_fields=set()):
    fields = {'scan_id': 'scan_id', 'iface': 'iface', 'type': 'type', 'gateway': 'gateway', 'dhcp': 'dhcp'}
    return fields if not exclude_fields else dict(filter(lambda x: x[0] not in exclude_fields, fields.items()))


def get_netproto_agent(agent_id, offset=0, limit=common.database_limit, select={}, search={}, sort={}, filters={}, nested=True):
    """
    Get info about an agent's network protocol
    """
    valid_select_fields = __get_netproto_fields()

    return get_item_agent(agent_id=agent_id, offset=offset, limit=limit, select=select,
                          search=search, sort=sort, filters=filters, allowed_sort_fields=valid_select_fields,
                          valid_select_fields=valid_select_fields, table='sys_netproto', array=True, nested=nested)


def __get_netiface_fields(exclude_fields=set()):
    fields = {'scan_id': 'scan_id', 'scan_time': 'scan_time', 'name': 'name', 'adapter': 'adapter', 'type': 'type',
              'state': 'state', 'mtu': 'mtu', 'mac': 'mac', 'tx_packets': 'tx_packets', 'rx_packets': 'rx_packets',
              'tx_bytes': 'tx_bytes', 'rx_bytes': 'rx_bytes', 'tx_errors': 'tx_errors', 'rx_errors': 'rx_errors',
              'tx_dropped': 'tx_dropped', 'rx_dropped': 'rx_dropped'}
    return fields if not exclude_fields else dict(filter(lambda x: x[0] not in exclude_fields, fields.items()))


def get_netiface_agent(agent_id, offset=0, limit=common.database_limit, select={}, search={}, sort={}, filters={}, nested=True):
    """
    Get info about an agent's network interface
    """
    valid_select_fields = __get_netiface_fields()

    return get_item_agent(agent_id=agent_id, offset=offset, limit=limit, select=select,
                         search=search, sort=sort, filters=filters, allowed_sort_fields=valid_select_fields,
                         valid_select_fields=valid_select_fields, table='sys_netiface', array=True, nested=nested)


def get_network_agent(agent_id, offset=0, limit=common.database_limit, select={}, search={}, sort={}, filters={}, nested=True):
    """
    Get info about all agent's network interface
    """
    valid_select_fields = [{key: '{}.{}'.format(table_name, value) for key, value in fields.items()} for table_name, fields in
                            zip(['sys_netiface', 'sys_netproto', 'sys_netaddr'], [__get_netiface_fields({'name'}),
                                                                                  __get_netproto_fields({'type', 'scan_id', 'scan_time'}),
                                                                                  __get_netaddr_fields({'scan_id','scan_time'})])]
    valid_select_fields = functools.reduce(lambda d, src: d.update(src) or d, valid_select_fields, {})

    if filters:
        pass
    else:
        filters = {'sys_netiface.name': 'sys_netproto.iface', 'sys_netiface.scan_id': 'sys_netproto.scan_id',
                   'sys_netproto.type': 'sys_netaddr.proto', 'sys_netaddr.scan_id': 'sys_netproto.scan_id'}

    return get_item_agent(agent_id=agent_id, offset=offset, limit=limit, select=select,
                          search=search, sort=sort, filters=filters, allowed_sort_fields=valid_select_fields,
                          valid_select_fields=valid_select_fields, table='sys_netiface, sys_netproto, sys_netaddr',
                          array=True, nested=nested)


def _get_agent_items(func, offset, limit, select, filters, search, sort, array=False):
    agents, result = Agent.get_agents_overview(select={'fields': ['id']})['items'], []

    total = 0

    for agent in agents:
        items = func(agent_id = agent['id'], select = select, filters = filters, limit = limit, offset = offset, search = search, sort=sort, nested=False)
        if items == {}:
            continue

        total += 1 if not array else items['totalItems']
        items = [items] if not array else items['items']

        for item in items:
            if 0 < limit <= len(result):
                break
            item['agent_id'] = agent['id']
            result.append(item)

    if result:
        if sort and sort['fields']:
            result = sorted(result, key=itemgetter(sort['fields'][0]), reverse=True if sort['order'] == "desc" else False)

        fields_to_nest, non_nested = get_fields_to_nest(result[0].keys(), '_')
    return {'items': list(map(lambda x: plain_dict_to_nested_dict(x, fields_to_nest, non_nested), result)), 'totalItems': total}


def get_packages(offset=0, limit=common.database_limit, select=None, filters={}, search={}, sort={}):
    return _get_agent_items(func=get_packages_agent, offset=offset, limit=limit, select=select,
                            filters=filters, search=search, sort=sort, array=True)


def get_os(filters={}, offset=0, limit=common.database_limit, select={}, search={}, sort={}):
    return _get_agent_items(func=get_os_agent, offset=offset, limit=limit, select=select,
                            filters=filters, search=search, sort=sort)


def get_hardware(offset=0, limit=common.database_limit, select=None, sort=None, filters={}, search={}):
    return _get_agent_items(func=get_hardware_agent, offset=offset, limit=limit, select=select,
                            filters=filters, search=search, sort=sort)


def get_processes(offset=0, limit=common.database_limit, select=None, sort=None, filters={}, search={}):
    return _get_agent_items(func=get_processes_agent, offset=offset, limit=limit, select=select,
                            filters=filters, search=search, sort=sort, array=True)


def get_ports(offset=0, limit=common.database_limit, select=None, sort=None, filters={}, search={}):
    return _get_agent_items(func=get_ports_agent, offset=offset, limit=limit, select=select,
                            filters=filters, search=search, sort=sort, array=True)


def get_netaddr(offset=0, limit=common.database_limit, select=None, sort=None, filters={}, search={}):
    return _get_agent_items(func=get_netaddr_agent, offset=offset, limit=limit, select=select,
                            filters=filters, search=search, sort=sort, array=True)


def get_netproto(offset=0, limit=common.database_limit, select=None, sort=None, filters={}, search={}):
    return _get_agent_items(func=get_netproto_agent, offset=offset, limit=limit, select=select,
                            filters=filters, search=search, sort=sort, array=True)


def get_netiface(offset=0, limit=common.database_limit, select=None, sort=None, filters={}, search={}):
    return _get_agent_items(func=get_netiface_agent, offset=offset, limit=limit, select=select,
                            filters=filters, search=search, sort=sort, array=True)

def get_network(offset=0, limit=common.database_limit, select=None, sort=None, filters={}, search={}):
    return _get_agent_items(func=get_network_agent, offset=offset, limit=limit, select=select,
                            filters=filters, search=search, sort=sort, array=True)
