#!/usr/bin/env python
# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from unittest.mock import patch

import pytest

from wazuh.exception import WazuhException
from wazuh.rootcheck import run, clear, last_scan, get_cis, get_pci, print_db


def get_random_status():
    return {'status': 'random'}


@pytest.mark.parametrize('agent_id', [
    '000',
    '001',
    '002',
    '003'
])
def test_rootcheck_run(agent_id):
    result = run(agent_id=agent_id)
    assert isinstance(result, str)


def test_rootcheck_run_all():
    result = run(all_agents=True)
    assert isinstance(result, str)


@patch('wazuh.rootcheck.Agent.get_basic_information', side_effect=get_random_status)
def test_rootcheck_run_status(mocked_status):
    with pytest.raises(WazuhException, match='.* 1601 .*'):
        run(agent_id='001')


@pytest.mark.parametrize('agent_id', [
    '000',
    '001',
    '002',
    '003'
])
def test_rootcheck_clear(agent_id):
    result = clear(agent_id=agent_id)
    assert isinstance(result, str)


def test_rootcheck_clear_all():
    result = clear(all_agents=True)
    assert isinstance(result, str)


@pytest.mark.parametrize('agent_id', [
    '000',
    '001',
    '002',
    '003'
])
def test_rootcheck_last_scan(agent_id):
    result = last_scan(agent_id)
    assert isinstance(result, dict)


@pytest.mark.parametrize('agent_id', [
    '000',
    '001',
    '002',
    '003'
])
def test_rootcheck_pci(agent_id):
    result = get_pci(agent_id=agent_id)
    assert isinstance(result, dict)


@pytest.mark.parametrize('agent_id', [
    '000',
    '001',
    '002',
    '003'
])
def test_rootcheck_pci(agent_id):
    result = get_cis(agent_id=agent_id)
    assert isinstance(result, dict)
