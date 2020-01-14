
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
from mock import patch

import os
import sys

test_path = os.path.abspath(os.path.dirname(os.path.realpath(__file__)))


class TestModelPolicyDtWorkflowDriverServiceInstance(unittest.TestCase):
    def setUp(self):

        self.sys_path_save = sys.path

        config = os.path.join(test_path, "../test_config.yaml")
        from xosconfig import Config
        Config.clear()
        Config.init(config, 'synchronizer-config-schema.yaml')

        from xossynchronizer.mock_modelaccessor_build import mock_modelaccessor_config
        mock_modelaccessor_config(test_path, [("dt-workflow-driver", "dt-workflow-driver.xproto"),
                                              ("olt-service", "volt.xproto"),
                                              ("rcord", "rcord.xproto")])

        import xossynchronizer.modelaccessor
        import mock_modelaccessor
        reload(mock_modelaccessor)  # in case nose2 loaded it in a previous test
        reload(xossynchronizer.modelaccessor)      # in case nose2 loaded it in a previous test

        from xossynchronizer.modelaccessor import model_accessor
        from model_policy_dt_workflow_driver_serviceinstance import DtWorkflowDriverServiceInstancePolicy, DtHelpers
        self.DtHelpers = DtHelpers

        # import all class names to globals
        for (k, v) in model_accessor.all_model_classes.items():
            globals()[k] = v

        # Some of the functions we call have side-effects. For example, creating a VSGServiceInstance may lead to
        # creation of tags. Ideally, this wouldn't happen, but it does. So make sure we reset the world.
        model_accessor.reset_all_object_stores()

        self.policy = DtWorkflowDriverServiceInstancePolicy(model_accessor=model_accessor)
        self.si = DtWorkflowDriverServiceInstance()
        self.si.owner = DtWorkflowDriverService()
        self.si.serial_number = "BRCM1234"

    def tearDown(self):
        sys.path = self.sys_path_save

    def test_update_onu(self):

        onu = ONUDevice(
            serial_number="BRCM1234",
            admin_state="ENABLED"
        )
        with patch.object(ONUDevice.objects, "get_items") as get_onu, \
                patch.object(onu, "save") as onu_save:
            get_onu.return_value = [onu]

            self.policy.update_onu("brcm1234", "ENABLED")
            onu_save.assert_not_called()

            self.policy.update_onu("brcm1234", "DISABLED")
            self.assertEqual(onu.admin_state, "DISABLED")
            onu_save.assert_called_with(
                always_update_timestamp=True, update_fields=[
                    'admin_state', 'serial_number', 'updated'])

    def test_enable_onu(self):
        with patch.object(self.DtHelpers, "validate_onu") as validate_onu, \
                patch.object(self.policy, "update_onu") as update_onu:
            validate_onu.return_value = [True, "valid onu"]

            self.policy.process_onu_state(self.si)

            update_onu.assert_called_once()
            update_onu.assert_called_with("BRCM1234", "ENABLED")

            self.assertIn("valid onu", self.si.status_message)

    def test_disable_onu(self):
        with patch.object(self.DtHelpers, "validate_onu") as validate_onu, \
                patch.object(self.policy, "update_onu") as update_onu:
            validate_onu.return_value = [False, "invalid onu"]

            self.policy.process_onu_state(self.si)

            update_onu.assert_called_once()
            update_onu.assert_called_with("BRCM1234", "DISABLED")

            self.assertIn("invalid onu", self.si.status_message)

    def test_handle_update_validate_onu(self):
        """
        Testing that handle_update calls validate_onu with the correct parameters
        when necessary
        """
        with patch.object(self.policy, "process_onu_state") as process_onu_state, \
                patch.object(self.policy, "update_onu") as update_onu, \
                patch.object(self.policy, "get_subscriber") as get_subscriber:
            update_onu.return_value = None
            get_subscriber.return_value = None

            self.si.admin_onu_state = "AWAITING"
            self.si.oper_onu_status = "AWAITING"
            self.policy.handle_update(self.si)
            process_onu_state.assert_called_with(self.si)

            self.si.admin_onu_state = "ENABLED"
            self.si.oper_onu_status = "ENABLED"
            self.policy.handle_update(self.si)
            process_onu_state.assert_called_with(self.si)

            self.si.admin_onu_state = "DISABLED"
            self.si.oper_onu_status = "DISABLED"
            self.policy.handle_update(self.si)
            process_onu_state.assert_called_with(self.si)

    def test_get_subscriber(self):

        sub = RCORDSubscriber(
            onu_device="BRCM1234"
        )

        with patch.object(RCORDSubscriber.objects, "get_items") as get_subscribers:
            get_subscribers.return_value = [sub]

            res = self.policy.get_subscriber("BRCM1234")
            self.assertEqual(res, sub)

            res = self.policy.get_subscriber("brcm1234")
            self.assertEqual(res, sub)

            res = self.policy.get_subscriber("foo")
            self.assertEqual(res, None)

    def test_update_subscriber_with_onu_event(self):

        sub = RCORDSubscriber(
            onu_device="BRCM1234",
            status="pre-provisioned"
        )

        self.assertEqual(sub.status, "pre-provisioned")

        with patch.object(sub, "save") as sub_save:
            self.si.oper_onu_status = "AWAITING"
            self.policy.update_subscriber(sub, self.si)
            self.assertEqual(sub.status, "pre-provisioned")
            sub_save.assert_not_called()
            sub_save.reset_mock()

            self.si.oper_onu_status = "ENABLED"
            self.si.admin_onu_state = "ENABLED"
            self.policy.update_subscriber(sub, self.si)
            self.assertEqual(sub.status, "enabled")
            sub_save.assert_called()
            sub_save.reset_mock()

            self.si.oper_onu_status = "DISABLED"
            self.policy.update_subscriber(sub, self.si)
            # FIXME: the result should be disabled, but for now we force it to remain enabled
            self.assertEqual(sub.status, "enabled")
            # sub_save.assert_called()
            sub_save.reset_mock()

    def test_not_update_subscriber_with_auth_events(self):

        sub = RCORDSubscriber(
            onu_device="BRCM1234"
        )

        self.si.status_message = "some content"
        self.si.oper_onu_status = "ENABLED"

        with patch.object(sub, "save") as sub_save:
            self.si.authentication_state = "AWAITING"
            self.policy.update_subscriber(sub, self.si)
            self.assertEqual(sub.status, "enabled")
            sub_save.assert_not_called()
            sub_save.reset_mock()
            sub.status = "enabled"

            self.si.authentication_state = "REQUESTED"
            self.policy.update_subscriber(sub, self.si)
            self.assertEqual(sub.status, "enabled")
            sub_save.assert_not_called()
            sub_save.reset_mock()
            sub.status = "enabled"

            self.si.authentication_state = "STARTED"
            self.policy.update_subscriber(sub, self.si)
            self.assertEqual(sub.status, "enabled")
            sub_save.assert_not_called()
            sub_save.reset_mock()
            sub.status = "enabled"

            self.si.authentication_state = "APPROVED"
            self.policy.update_subscriber(sub, self.si)
            self.assertEqual(sub.status, "enabled")
            sub_save.assert_not_called()
            sub_save.reset_mock()
            sub.status = "enabled"

            self.si.authentication_state = "DENIED"
            self.policy.update_subscriber(sub, self.si)
            self.assertEqual(sub.status, "enabled")
            sub_save.assert_not_called()
            sub_save.reset_mock()
            sub.status = "enabled"

    def test_update_subscriber_not(self):
        sub = RCORDSubscriber(
            onu_device="BRCM1234"
        )

        self.si.oper_onu_status = "ENABLED"
        sub.status = "enabled"

        with patch.object(sub, "save") as sub_save:
            self.si.authentication_state = "AWAITING"
            self.policy.update_subscriber(sub, self.si)
            sub_save.assert_not_called()

            self.si.authentication_state = "REQUESTED"
            self.policy.update_subscriber(sub, self.si)
            sub_save.assert_not_called()

            self.si.authentication_state = "STARTED"
            self.policy.update_subscriber(sub, self.si)
            sub_save.assert_not_called()

            self.si.authentication_state = "APPROVED"
            self.policy.update_subscriber(sub, self.si)
            sub_save.assert_not_called()

            self.si.authentication_state = "DENIED"
            self.policy.update_subscriber(sub, self.si)
            sub_save.assert_not_called()

    def test_update_subscriber_ipcp_with_exiting_ip(self):
        sub = RCORDSubscriber(
            id=10,
            onu_device="BRCM1234"
        )

        ip = RCORDIpAddress(
            subscriber_id=sub.id,
            ip='10.11.2.23'
        )

        self.si.pppoe_state = "CONNECTED"
        self.si.authentication_state = "APPROVED"
        self.si.oper_onu_status = "ENABLED"
        self.si.ipcp_state = "CONF_ACK"
        self.si.ip_address = "10.11.2.23"
        self.si.mac_address = "4321"

        with patch.object(sub, "save") as sub_save, \
                patch.object(RCORDIpAddress.objects, "get_items") as get_ips, \
                patch.object(ip, "save_changed_fields") as ip_mock:

            get_ips.return_value = [ip]
            ip_mock.return_value = []

            self.policy.update_subscriber(sub, self.si)
            sub_save.assert_called_with(always_update_timestamp=False,
                update_fields=['id', 'mac_address', 'onu_device'])
            self.assertEqual(sub.mac_address, self.si.mac_address)

            ip_mock.assert_called_with()

    def test_update_subscriber_ipcp_with_new_ip(self):
        sub = RCORDSubscriber(
            id=10,
            onu_device="BRCM1234"
        )

        self.si.pppoe_state = "CONNECTED"
        self.si.oper_onu_status = "ENABLED"
        self.si.authentication_state = "APPROVED"
        self.si.ipcp_state = "CONF_ACK"
        self.si.ip_address = "10.11.2.23"
        self.si.mac_address = "4321"

        with patch.object(sub, "save") as sub_save, \
                patch.object(RCORDIpAddress, "save", autospec=True) as ip_mock:

            ip_mock.return_value = []

            self.policy.update_subscriber(sub, self.si)
            sub_save.assert_called_with(always_update_timestamp=False,
                                        update_fields=['id', 'mac_address', 'onu_device'])
            self.assertEqual(sub.mac_address, self.si.mac_address)

            saved_ip = ip_mock.call_args[0][0]
            self.assertEqual(saved_ip.ip, self.si.ip_address)
            self.assertEqual(saved_ip.subscriber_id, sub.id)
            self.assertEqual(saved_ip.description, "IPCP Assigned IP Address")

    def test_handle_update_subscriber(self):
        self.si.admin_onu_state = "DISABLED"

        sub = RCORDSubscriber(
            onu_device="BRCM1234"
        )

        with patch.object(self.policy, "get_subscriber") as get_subscriber, \
                patch.object(self.policy, "update_onu") as update_onu, \
                patch.object(self.policy, "update_subscriber") as update_subscriber:

            get_subscriber.return_value = None
            self.policy.handle_update(self.si)
            update_onu.assert_called_with(sub.onu_device, "DISABLED")
            self.assertEqual(update_subscriber.call_count, 0)

            get_subscriber.return_value = sub
            self.policy.handle_update(self.si)
            update_subscriber.assert_called_with(sub, self.si)

    def test_process_auth_state(self):
        # testing change in admin_onu_state
        self.si.admin_onu_state = "DISABLED"
        self.si.oper_onu_status = "ENABLED"
        self.si.authentication_state, "APPROVED"

        self.policy.validate_states(self.si)
        self.assertEqual(self.si.authentication_state, "AWAITING")

        # testing change in oper_onu_status
        self.si.admin_onu_state = "ENABLED"
        self.si.oper_onu_status = "DISABLED"
        self.si.authentication_state, "APPROVED"

        self.policy.validate_states(self.si)
        self.assertEqual(self.si.authentication_state, "AWAITING")


if __name__ == '__main__':
    sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), ".."))
    unittest.main()
