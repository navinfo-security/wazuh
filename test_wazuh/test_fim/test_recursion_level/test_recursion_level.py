# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import os
import re
import pytest
import sys

from wazuh_testing.fim import (LOG_FILE_PATH, callback_audit_event_too_long, regular_file_cud)
from wazuh_testing.tools import FileMonitor, load_wazuh_configurations, set_configuration


# Variables

prefix = os.path.join('C:', os.sep) if sys.platform == 'win32' else os.sep

dir_no_recursion = os.path.join(prefix, 'test_no_recursion')
dir_recursion_1 = os.path.join(prefix, os.sep, 'test_recursion_1')
dir_recursion_5 = os.path.join(prefix, os.sep, 'test_recursion_5')
dir_recursion_320 = os.path.join(prefix, os.sep, 'test_recursion_320')
subdir = "subdir"

dir_no_recursion_space = os.path.join(prefix, 'test no recursion')
dir_recursion_1_space = os.path.join(prefix, 'test recursion 1')
dir_recursion_5_space = os.path.join(prefix, 'test recursion 5')
dir_recursion_320_space = os.path.join(prefix, 'test recursion 320')
subdir_space = "sub dir "

test_directories = [dir_no_recursion, dir_recursion_1, dir_recursion_5, dir_recursion_320, dir_no_recursion_space,
                    dir_recursion_1_space, dir_recursion_5_space, dir_recursion_320_space]

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
conf_name = "wazuh_recursion_windows.yaml" if sys.platform == "win32" else "wazuh_recursion.yaml"
configurations_path = os.path.join(test_data_path, conf_name)
wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)


# configurations

configurations = load_wazuh_configurations(configurations_path, __name__,
                                           params=[{'FIM_MODE': '', 'CHECK': {'check_all': 'yes'}},
                                                   {'FIM_MODE': '', 'CHECK': {'check_inode': 'no'}},
                                                   {'FIM_MODE': {'realtime': 'yes'}, 'CHECK': {'check_all': 'yes'}},
                                                   {'FIM_MODE': {'realtime': 'yes'}, 'CHECK': {'check_inode': 'no'}},
                                                   {'FIM_MODE': {'whodata': 'yes'}, 'CHECK': {'check_all': 'yes'}},
                                                   {'FIM_MODE': {'whodata': 'yes'}, 'CHECK': {'check_inode': 'no'}}
                                                   ],
                                           metadata=[{'fim_mode': 'scheduled', 'check': 'all'},
                                                     {'fim_mode': 'scheduled', 'check': 'inode'},
                                                     {'fim_mode': 'realtime', 'check': 'all'},
                                                     {'fim_mode': 'realtime', 'check': 'inode'},
                                                     {'fim_mode': 'whodata', 'check': 'all'},
                                                     {'fim_mode': 'whodata', 'check': 'inode'}
                                                     ]
                                           )


# Functions

def check_config_applies(applies_to_config, get_configuration):
    """Checks if the processed conf file matches with the one specified by parameter.
    If not, the test is skipped.
    :param applies_to_config string The .conf file name to apply.
    """
    if not re.search(applies_to_config, get_configuration):
        pytest.skip("Does not apply to this config file")


def recursion_test(dirname, subdirname, recursion_level, timeout=1, threshold_true=2, threshold_false=2,
                   is_scheduled=False):
    """Checks recursion_level functionality over the first and last n-directories of the dirname hierarchy
    by creating, modifying and deleting some files in them. It will create all directories and
    subdirectories needed using the info provided by parameter.
    :param dirname string The path being monitored by syscheck (indicated in the .conf file)
    :param subdirname string The name of the subdirectories that will be created during the execution for testing purpouses.
    :param recursion_level int Recursion level. Also used as the number of subdirectories to be created and checked for the current test.
    :param timeout int Max time to wait until an event is raised.
    :param threshold_true Number of directories where the test will monitor events
    :param threshold_false Number of directories exceding the specified recursion_level to verify events are not raised
    :param is_scheduled bool If True the internal date will be modified to trigger scheduled checks by syschecks. False if realtime or Whodata.
    """
    path = dirname
    try:
        # Check True (Within the specified recursion level)
        for n in range(recursion_level):
            path = os.path.join(path, subdirname + str(n + 1))
            if ((recursion_level < threshold_true * 2) or
                (recursion_level >= threshold_true * 2 and n < threshold_true) or
                (recursion_level >= threshold_true * 2 and n > recursion_level - threshold_true)):
                check_event_too_long()
                regular_file_cud(path, wazuh_log_monitor, time_travel=is_scheduled, min_timeout=timeout)

        # Check False (exceding the specified recursion_level)
        for n in range(recursion_level, recursion_level + threshold_false):
            check_event_too_long()
            path = os.path.join(path, subdirname + str(n + 1))
            regular_file_cud(path, wazuh_log_monitor, time_travel=is_scheduled, min_timeout=timeout, triggers_event=False)

    except (TimeoutError, AssertionError):
        check_event_too_long()
    except OSError as ex:
        if ex.winerror == 206:
            pytest.exit(msg="Reached Windows maximum path length.", returncode=pytest.ExitCode.OK)


def check_event_too_long():
    """Checks if the `Event to long` message was raised due to Whodata path length limitation."""
    try:
        event = wazuh_log_monitor.start(timeout=1,
                                        callback=callback_audit_event_too_long,
                                        update_position=False).result()
        if event:
            pytest.exit(msg="Reached Whodata maximum path length.", returncode=pytest.ExitCode.OK)
        pytest.fail("No 'Event Too Long' message was raised.")
    except TimeoutError:
        pass


# Fixtures

@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    return request.param


# Tests

@pytest.mark.parametrize('dirname, subdirname, recursion_level', [
    (dir_no_recursion, subdir, 0),
    (dir_no_recursion_space, subdir_space, 0),
    (dir_recursion_1, subdir, 1),
    (dir_recursion_1_space, subdir_space, 1),
    (dir_recursion_5, subdir, 5),
    (dir_recursion_5_space, subdir_space, 5),
    (dir_recursion_320, subdir, 320),
    (dir_recursion_320_space, subdir_space, 320)
])
def test_recursion_level(dirname, subdirname, recursion_level,
                         get_configuration, configure_environment,
                         restart_syscheckd, wait_for_initial_scan):
    """Checks if files are correctly detected by syscheck with recursion level using scheduled, realtime and whodata monitoring
    This test is intended to be used with valid ignore configurations. It applies RegEx to match the name 
    of the configuration file where the test applies. If the configuration file does not match the test 
    is skipped.
    :param dirname string The path being monitored by syscheck (indicated in the .conf file)
    :param subdirname string The name of the subdirectories that will be created during the execution for testing purpouses.
    :param recursion_level int Recursion level. Also used as the number of subdirectories to be created and checked for the current test.
    """
    recursion_test(dirname, subdirname, recursion_level, timeout=1,
                   is_scheduled=get_configuration['metadata']['fim_mode'] == 'scheduled')
