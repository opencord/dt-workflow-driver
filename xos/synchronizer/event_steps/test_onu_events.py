# Copyright 2020-present Open Networking Foundation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import unittest
from mock import patch, Mock
import json

import os
import sys

test_path = os.path.abspath(os.path.dirname(os.path.realpath(__file__)))


class TestSyncOLTDevice(unittest.TestCase):

    def setUp(self):

        self.sys_path_save = sys.path

        # Setting up the config module
        from xosconfig import Config
        config = os.path.join(test_path, "../test_config.yaml")
        Config.clear()
        Config.init(config, "synchronizer-config-schema.yaml")
        # END Setting up the config module

        from xossynchronizer.mock_modelaccessor_build import mock_modelaccessor_config
        mock_modelaccessor_config(test_path, [("dt-workflow-driver", "dt-workflow-driver.xproto"),
                                              ("olt-service", "volt.xproto"),
                                              ("rcord", "rcord.xproto")])

        import xossynchronizer.modelaccessor
        import mock_modelaccessor
        reload(mock_modelaccessor)  # in case nose2 loaded it in a previous test
        reload(xossynchronizer.modelaccessor)      # in case nose2 loaded it in a previous test

        from xossynchronizer.modelaccessor import model_accessor
        from onu_event import ONUEventStep

        # import all class names to globals
        for (k, v) in model_accessor.all_model_classes.items():
            globals()[k] = v

        self.model_accessor = model_accessor
        self.log = Mock()

        self.event_step = ONUEventStep(model_accessor=self.model_accessor, log=self.log)

        self.event = Mock()
        self.event_dict = {
            'status': 'activated',
            'serialNumber': 'BRCM1234',
            'deviceId': 'of:109299321',
            'portNumber': '16'
        }
        self.event.value = json.dumps(self.event_dict)

        self.pppoe = DtWorkflowDriverService(name="dt-workflow-driver")

    def tearDown(self):
        sys.path = self.sys_path_save

    def test_create_instance(self):

        with patch.object(DtWorkflowDriverServiceInstance.objects, "get_items") as dt_si_mock, \
                patch.object(DtWorkflowDriverService.objects, "get_items") as service_mock, \
                patch.object(DtWorkflowDriverServiceInstance, "save", autospec=True) as mock_save:

            dt_si_mock.return_value = []
            service_mock.return_value = [self.pppoe]

            self.event_step.process_event(self.event)

            dt_si = mock_save.call_args[0][0]

            self.assertEqual(mock_save.call_count, 1)

            self.assertEqual(dt_si.serial_number, self.event_dict['serialNumber'])
            self.assertEqual(dt_si.of_dpid, self.event_dict['deviceId'])
            self.assertEqual(dt_si.uni_port_id, long(self.event_dict['portNumber']))
            # Receiving an ONU event doesn't change the admin_onu_state until the model policy runs
            self.assertEqual(dt_si.admin_onu_state, "AWAITING")
            self.assertEqual(dt_si.oper_onu_status, "ENABLED")

    def test_reuse_instance(self):

        si = DtWorkflowDriverServiceInstance(
            serial_number=self.event_dict["serialNumber"],
            of_dpid="foo",
            uni_port_id="foo"
        )

        with patch.object(DtWorkflowDriverServiceInstance.objects, "get_items") as dt_si_mock, \
                patch.object(DtWorkflowDriverServiceInstance, "save", autospec=True) as mock_save:

            dt_si_mock.return_value = [si]

            self.event_step.process_event(self.event)

            dt_si = mock_save.call_args[0][0]

            self.assertEqual(mock_save.call_count, 1)

            self.assertEqual(dt_si.serial_number, self.event_dict['serialNumber'])
            self.assertEqual(dt_si.of_dpid, self.event_dict['deviceId'])
            self.assertEqual(dt_si.uni_port_id, long(self.event_dict['portNumber']))
            # Receiving an ONU event doesn't change the admin_onu_state until the model policy runs
            self.assertEqual(dt_si.admin_onu_state, "AWAITING")
            self.assertEqual(dt_si.oper_onu_status, "ENABLED")

    def test_disable_onu(self):
        self.event_dict = {
            'status': 'disabled',
            'serialNumber': 'BRCM1234',
            'deviceId': 'of:109299321',
            'portNumber': '16',
        }

        si = DtWorkflowDriverServiceInstance(
            serial_number=self.event_dict["serialNumber"],
            of_dpid="foo",
            uni_port_id="foo",
            admin_onu_state="ENABLED",
            oper_onu_status="ENABLED",
        )

        self.event.value = json.dumps(self.event_dict)

        with patch.object(DtWorkflowDriverServiceInstance.objects, "get_items") as dt_si_mock, \
                patch.object(DtWorkflowDriverServiceInstance, "save_changed_fields", autospec=True) as mock_save:
            dt_si_mock.return_value = [si]

            self.event_step.process_event(self.event)

            dt_si = mock_save.call_args[0][0]

            self.assertEqual(mock_save.call_count, 1)

            # Receiving an ONU event doesn't change the admin_onu_state until the model policy runs
            self.assertEqual(dt_si.admin_onu_state, 'ENABLED')
            self.assertEqual(dt_si.oper_onu_status, 'DISABLED')

    def test_enable_onu(self):
        self.event_dict = {
            'status': 'activated',
            'serialNumber': 'BRCM1234',
            'deviceId': 'of:109299321',
            'portNumber': '16',
        }

        si = DtWorkflowDriverServiceInstance(
            serial_number=self.event_dict["serialNumber"],
            of_dpid="foo",
            uni_port_id="foo",
            admin_onu_state="DISABLED",
            oper_onu_status="DISABLED",
        )

        self.event.value = json.dumps(self.event_dict)

        with patch.object(DtWorkflowDriverServiceInstance.objects, "get_items") as dt_si_mock, \
                patch.object(DtWorkflowDriverServiceInstance, "save_changed_fields", autospec=True) as mock_save:
            dt_si_mock.return_value = [si]

            self.event_step.process_event(self.event)

            dt_si = mock_save.call_args[0][0]

            self.assertEqual(mock_save.call_count, 1)

            # Receiving an ONU event doesn't change the admin_onu_state until the model policy runs
            self.assertEqual(dt_si.admin_onu_state, 'DISABLED')
            self.assertEqual(dt_si.oper_onu_status, 'ENABLED')



if __name__ == '__main__':
    sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), ".."))  # for import of helpers.py
    unittest.main()
