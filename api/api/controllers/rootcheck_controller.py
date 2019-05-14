# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import asyncio
import logging

import dateutil.parser

import wazuh.rootcheck as rootcheck
from api.models.base_model_ import Data
from api.util import remove_nones_to_dict, exception_handler, parse_api_param, raise_if_exc
from wazuh.cluster.dapi.dapi import DistributedAPI

loop = asyncio.get_event_loop()
logger = logging.getLogger('wazuh')


@exception_handler
def put_rootcheck(pretty=False, wait_for_complete=False):
    """Run rootcheck scan

    Runs syscheck and rootcheck in all agents (Wazuh launches both processes simultaneously).

    :param pretty: Show results in human-readable format 
    :type pretty: bool
    :param wait_for_complete: Disable timeout response 
    :type wait_for_complete: bool
    """

    f_kwargs = {'all_agents': True}

    dapi = DistributedAPI(f=rootcheck.run,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='distributed_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          pretty=pretty,
                          logger=logger
                          )
    data = raise_if_exc(loop.run_until_complete(dapi.distribute_function()))

    return data, 200


@exception_handler
def delete_rootcheck(pretty=False, wait_for_complete=False):
    """Clear rootcheck

    Clears rootcheck scan results in all agents.

    :param pretty: Show results in human-readable format 
    :type pretty: bool
    :param wait_for_complete: Disable timeout response 
    :type wait_for_complete: bool
    """

    f_kwargs = {'all_agents': True}

    dapi = DistributedAPI(f=rootcheck.clear,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='distributed_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          pretty=pretty,
                          logger=logger
                          )
    data = raise_if_exc(loop.run_until_complete(dapi.distribute_function()))

    return data, 200


@exception_handler
def get_rootcheck_agent(agent_id, pretty=False, wait_for_complete=False, offset=0, limit=None, 
                        select=None, sort=None, search=None, q='', status=None, pci='all', cis='all'):
    """Get Rootcheck database

    Returns rootcheck findings and scan results in the specified agent.

    :param pretty: Show results in human-readable format 
    :type pretty: bool
    :param wait_for_complete: Disable timeout response 
    :type wait_for_complete: bool
    :param agent_id: Agent ID
    :type agent_id: str
    :param offset: First element to return in the collection
    :type offset: int
    :param limit: Maximum number of elements to return
    :type limit: int
    :param select: Select which fields to return (separated by comma)
    :type select: List[str]
    :param sort: Sorts the collection by a field or fields (separated by comma).
    Use +/- at the beginning to list in ascending or descending order.
    :type sort: str
    :param search: Looks for elements with the specified string
    :type search: str
    :param status: Filters by agent status. Use commas to enter multiple statuses.
    :type status: List[str]
    :param q: Query to filter results by. For example q&#x3D;&amp;quot;status&#x3D;Active&amp;quot;
    :type q: str
    :param status: Filter by scan status.
    :type status: str
    :param pci: Filters by PCI requirement.
    :type pci: str
    :param cis: Filters by CIS requirement.
    :type cis: str
    """

    filters = {'status': status, 'pci': pci, 'cis': cis}

    f_kwargs = {'agent_id': agent_id, 'offset': offset, 'limit': limit, 'select': select,
                'sort': parse_api_param(sort, 'sort'), 'search': parse_api_param(search, 'search'),
                'q': q, 'filters': filters}

    dapi = DistributedAPI(f=rootcheck.print_db,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='distributed_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          pretty=pretty,
                          logger=logger
                          )
    data = raise_if_exc(loop.run_until_complete(dapi.distribute_function()))
    response = Data(data)

    return response, 200


@exception_handler
def put_rootcheck_agent(agent_id, pretty=False, wait_for_complete=False):
    """Run rootcheck scan in an agent

    Runs syscheck and rootcheck scans in a specified agent (Wazuh launches both processes at the same time).

    :param pretty: Show results in human-readable format 
    :type pretty: bool
    :param wait_for_complete: Disable timeout response 
    :type wait_for_complete: bool
    :param agent_id: Agent ID
    :type agent_id: str
    """

    f_kwargs = {'agent_id': agent_id}

    dapi = DistributedAPI(f=rootcheck.run,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='distributed_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          pretty=pretty,
                          logger=logger
                          )
    data = raise_if_exc(loop.run_until_complete(dapi.distribute_function()))

    return data, 200


@exception_handler
def delete_rootcheck_agent(agent_id, pretty=False, wait_for_complete=False):
    """Clear rootcheck

    Clear rootcheck scan results for a specified agent.

    :param pretty: Show results in human-readable format 
    :type pretty: bool
    :param wait_for_complete: Disable timeout response 
    :type wait_for_complete: bool
    :param agent_id: Agent ID
    :type agent_id: str
    """

    f_kwargs = {'agent_id': agent_id}

    dapi = DistributedAPI(f=rootcheck.clear,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='distributed_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          pretty=pretty,
                          logger=logger
                          )
    data = raise_if_exc(loop.run_until_complete(dapi.distribute_function()))

    return data, 200


@exception_handler
def get_rootcheck_pci_agent(agent_id, pretty=False, wait_for_complete=False, offset=0, limit=None, 
                            sort=None, search=None):
    """Get PCI requirements

    Returns a list containing PCI requirements that have been detected by rootcheck scans.

    :param pretty: Show results in human-readable format 
    :type pretty: bool
    :param wait_for_complete: Disable timeout response 
    :type wait_for_complete: bool
    :param agent_id: Agent ID
    :type agent_id: str
    :param offset: First element to return in the collection
    :type offset: int
    :param limit: Maximum number of elements to return
    :type limit: int
    :param sort: Sorts the collection by a field or fields (separated by comma).
    Use +/- at the beginning to list in ascending or descending order.
    :type sort: str
    :param search: Looks for elements with the specified string
    :type search: str
    """

    f_kwargs = {'agent_id': agent_id, 'offset': offset, 'limit': limit,
                'sort': parse_api_param(sort, 'sort'), 'search': parse_api_param(search, 'search')}

    dapi = DistributedAPI(f=rootcheck.get_pci,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='distributed_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          pretty=pretty,
                          logger=logger
                          )
    data = raise_if_exc(loop.run_until_complete(dapi.distribute_function()))
    response = Data(data)

    return response, 200


@exception_handler
def get_rootcheck_cis_agent(agent_id, pretty=False, wait_for_complete=False, offset=0, limit=None, 
                            sort=None, search=None):
    """Get CIS requirements

    Returns a list containing CIS requirements that have been detected by rootcheck scans.

    :param pretty: Show results in human-readable format 
    :type pretty: bool
    :param wait_for_complete: Disable timeout response 
    :type wait_for_complete: bool
    :param agent_id: Agent ID
    :type agent_id: str
    :param offset: First element to return in the collection
    :type offset: int
    :param limit: Maximum number of elements to return
    :type limit: int
    :param sort: Sorts the collection by a field or fields (separated by comma).
    Use +/- at the beginning to list in ascending or descending order.
    :type sort: str
    :param search: Looks for elements with the specified string
    :type search: str
    """

    f_kwargs = {'agent_id': agent_id, 'offset': offset, 'limit': limit,
                'sort': parse_api_param(sort, 'sort'), 'search': parse_api_param(search, 'search')}

    dapi = DistributedAPI(f=rootcheck.get_cis,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='distributed_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          pretty=pretty,
                          logger=logger
                          )
    data = raise_if_exc(loop.run_until_complete(dapi.distribute_function()))
    response = Data(data)

    return response, 200


@exception_handler
def get_last_scan_agent(agent_id, pretty=False, wait_for_complete=False):
    """Get last rootcheck scan dates

    Returns when the last rootcheck scan started and ended.
    If the scan is still in progress the end date will be unknown.

    :param pretty: Show results in human-readable format 
    :type pretty: bool
    :param wait_for_complete: Disable timeout response 
    :type wait_for_complete: bool
    :param agent_id: Agent ID
    :type agent_id: str
    """

    f_kwargs = {'agent_id': agent_id}

    dapi = DistributedAPI(f=rootcheck.last_scan,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='distributed_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          pretty=pretty,
                          logger=logger
                          )
    data = raise_if_exc(loop.run_until_complete(dapi.distribute_function()))

    # Check if scan is running to set end to None
    if data["start"] is not None:
        start = raise_if_exc(dateutil.parser.parse(data["start"]))
        end = raise_if_exc(dateutil.parser.parse(data["end"]))
        if start > end:
            data["end"] = None

    response = Data(data)

    return response, 200
