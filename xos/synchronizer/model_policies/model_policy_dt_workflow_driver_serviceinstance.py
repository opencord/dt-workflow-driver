
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


from helpers import DtHelpers
from xossynchronizer.model_policies.policy import Policy

import os
import sys

sync_path = os.path.abspath(os.path.join(os.path.dirname(os.path.realpath(__file__)), ".."))
sys.path.append(sync_path)


class DeferredException(Exception):
    pass


class DtWorkflowDriverServiceInstancePolicy(Policy):
    model_name = "DtWorkflowDriverServiceInstance"

    def handle_create(self, si):
        self.logger.debug("MODEL_POLICY: handle_create for DtWorkflowDriverServiceInstance %s " % si.id)
        self.handle_update(si)

    def handle_update(self, si):
        self.logger.debug("MODEL_POLICY: handle_update for DtWorkflowDriverServiceInstance %s " %
                          (si.id), onu_state=si.admin_onu_state, authentication_state=si.authentication_state)

        # Changing ONU state can change auth state
        # Changing auth state can change IPCP state
        # So need to process in this order
        self.process_onu_state(si)

        self.validate_states(si)

        self.process_pppoe_state(si)
        self.process_ipcp_state(si)

        # handling the subscriber status
        # It's a combination of all the other states
        subscriber = self.get_subscriber(si.serial_number)
        if subscriber:
            self.update_subscriber(subscriber, si)

        if si.pppoe_state != "CONNECTED" or si.oper_onu_status != "ENABLED" or si.admin_onu_state != "ENABLED":
            # Clean-up of SI
            si.pppoe_session_id = ""
            si.ip_address = ""
            si.mac_address = ""

        si.save_changed_fields()

    # Check the whitelist to see if the ONU is valid.  If it is, make sure that it's enabled.
    def process_onu_state(self, si):
        [valid, message] = DtHelpers.validate_onu(self.model_accessor, self.logger, si)
        si.status_message = message
        if valid:
            si.admin_onu_state = "ENABLED"
            self.update_onu(si.serial_number, "ENABLED")
        else:
            si.admin_onu_state = "DISABLED"
            self.update_onu(si.serial_number, "DISABLED")

    def process_pppoe_state(self, si):
        pppoe_msgs = {
            "AWAITING": " - Awaiting PPPoE connection",
            "INITIATED": "",
            "CONNECTED": "",
            "DISCONNECTED": " - PPPoE session terminated",
        }
        si.status_message += pppoe_msgs[si.pppoe_state]

    def process_ipcp_state(self, si):
        ipcp_msgs = {
            "AWAITING": "",
            "CONF_ACK": " - IP address assigned",
            "CONF_REQUEST": ""
        }
        si.status_message += ipcp_msgs[si.ipcp_state]

    def validate_states(self, si):
        if si.pppoe_state != "CONNECTED" or si.oper_onu_status != "ENABLED" or si.admin_onu_state != "ENABLED":
            # Clean-up of SI
            si.ipcp_state = "AWAITING"
            si.authentication_state = "AWAITING"

    def update_onu(self, serial_number, admin_state):
        onu = [onu for onu in self.model_accessor.ONUDevice.objects.all() if onu.serial_number.lower()
               == serial_number.lower()][0]
        if onu.admin_state == "ADMIN_DISABLED":
            self.logger.debug(
                "MODEL_POLICY: ONUDevice [%s] has been manually disabled, not changing state to %s" %
                (serial_number, admin_state))
            return
        if onu.admin_state == admin_state:
            self.logger.debug(
                "MODEL_POLICY: ONUDevice [%s] already has admin_state to %s" %
                (serial_number, admin_state))
        else:
            self.logger.debug("MODEL_POLICY: setting ONUDevice [%s] admin_state to %s" % (serial_number, admin_state))
            onu.admin_state = admin_state
            onu.save_changed_fields(always_update_timestamp=True)

    def get_subscriber(self, serial_number):
        try:
            return [s for s in self.model_accessor.RCORDSubscriber.objects.all() if s.onu_device.lower()
                    == serial_number.lower()][0]
        except IndexError:
            # If the subscriber doesn't exist we don't do anything
            self.logger.debug(
                "MODEL_POLICY: subscriber does not exists for this SI, doing nothing",
                onu_device=serial_number)
            return None

    def update_subscriber_ip(self, subscriber, ip):
        # TODO check if the subscriber has an IP and update it,
        #  or create a new one
        try:
            ip = self.model_accessor.RCORDIpAddress.objects.filter(
                subscriber_id=subscriber.id,
                ip=ip
            )[0]
            self.logger.debug("MODEL_POLICY: found existing RCORDIpAddress for subscriber",
                              onu_device=subscriber.onu_device, subscriber_status=subscriber.status, ip=ip)
            ip.save_changed_fields()
        except IndexError:
            self.logger.debug(
                "MODEL_POLICY: Creating new RCORDIpAddress for subscriber",
                onu_device=subscriber.onu_device,
                subscriber_status=subscriber.status,
                ip=ip)
            ip = self.model_accessor.RCORDIpAddress(
                subscriber_id=subscriber.id,
                ip=ip,
                description="IPCP Assigned IP Address"
            )
            ip.save()

    def delete_subscriber_ip(self, subscriber, ip):
        try:
            ip = self.model_accessor.RCORDIpAddress.objects.filter(
                subscriber_id=subscriber.id,
                ip=ip
            )[0]
            self.logger.debug(
                "MODEL_POLICY: delete RCORDIpAddress for subscriber",
                onu_device=subscriber.onu_device,
                subscriber_status=subscriber.status,
                ip=ip)
            ip.delete()
        except BaseException:
            self.logger.warning("MODEL_POLICY: no RCORDIpAddress object found, cannot delete", ip=ip)

    def update_subscriber(self, subscriber, si):
        cur_status = subscriber.status
        if si.oper_onu_status == "ENABLED" and si.admin_onu_state == "ENABLED":
            subscriber.status = "enabled"
        # FIXME: SEBA-670
        # elif si.admin_onu_state == "DISABLED":
        #     subscriber.status = "disabled"

        # FIXME: we need subscriber to be always in enabled state to be able
        #  to handle pppoe authentication via thew asg/pppoe relay, otherwise
        #  packets will be dropped at the OLT.
        #  We should either create an intermediate state to allow passing
        #  traffic from the OLT to the ASG, or we should relay PPPPoE
        #  control packets from the OLT.

        if si.ipcp_state == "CONF_ACK" and si.ip_address:
            self.update_subscriber_ip(subscriber, si.ip_address)
        else:
            self.delete_subscriber_ip(subscriber, si.ip_address)

        if si.ipcp_state == "CONF_ACK" and si.mac_address:
            subscriber.mac_address = si.mac_address
        else:
            subscriber.mac_address = ""

        important_changes = cur_status != subscriber.status
        if important_changes or si.pppoe_state == "DISCONNECTED" or si.ipcp_state == "CONF_ACK":
            # NOTE SEBA-744
            # Trigger sync_step only when the subscriber state change
            self.logger.debug(
                "MODEL_POLICY: updating subscriber",
                onu_device=subscriber.onu_device,
                authentication_state=si.authentication_state,
                subscriber_status=subscriber.status,
                always_update_timestamp=important_changes)
            subscriber.save_changed_fields(always_update_timestamp=important_changes)
        else:
            self.logger.debug("MODEL_POLICY: subscriber status has not changed", onu_device=subscriber.onu_device,
                              authentication_state=si.authentication_state, subscriber_status=subscriber.status)

    def handle_delete(self, si):
        pass
