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

import json
from xossynchronizer.event_steps.eventstep import EventStep
from helpers import DtHelpers


class SubscriberPppoeEventStep(EventStep):
    topics = ["bng.pppoe"]
    technology = "kafka"

    to_pppoe = {
        "SESSION_INIT": "INITIATED",
        "SESSION_CONFIRMATION": "CONNECTED",
        "SESSION_TERMINATION": "DISCONNECTED"
    }
    to_ipcp = {
        "IPCP_CONF_ACK": "CONF_ACK",
        "IPCP_CONF_REQ": "CONF_REQUEST"
    }

    to_auth = {
        "AUTH_REQ": "STARTED",
        "AUTH_SUCCESS": "APPROVED",
        "AUTH_FAILED": "DENIED"
    }

    def __init__(self, *args, **kwargs):
        super(SubscriberPppoeEventStep, self).__init__(*args, **kwargs)

    def process_event(self, event):
        value = json.loads(event.value)
        self.log.info("bng.pppoe: Got event for subscriber", event_value=value)

        si = DtHelpers.find_or_create_dt_si(self.model_accessor, self.log, value)
        self.log.debug("bng.pppoe: Updating service instance", si=si)
        # Map messageType to the different SI states
        messageType = value["eventType"]
        if messageType in self.to_pppoe.keys():
            si.pppoe_state = self.to_pppoe[messageType]
        if messageType in self.to_ipcp.keys():
            si.ipcp_state = self.to_ipcp[messageType]
        if messageType in self.to_auth.keys():
            si.authentication_state = self.to_auth[messageType]
        si.ip_address = value["ipAddress"]
        si.mac_address = value["macAddress"]
        si.pppoe_session_id = value["sessionId"]
        si.save_changed_fields(always_update_timestamp=True)
