# DT Workflow Driver Service

This service implements the ONU and Subscriber management logic for a sample PPPoE-based workflow.
It's also a good start if you need to implement different logic to suit your use case.

> NOTE: This service depends on models contained in the R-CORD and OLT Services, so make sure that the `rcord-synchronizer` and `volt-synchronzier` are running

## Models

This service is composed of the following models:

- `DtWorkflowDriverServiceInstance`. This model holds various state associated with the state machine for validating a subscriber's ONU.
    - `serial_number`. Serial number of ONU.
    - NOTE: we might consider creating ONU always in APPROVED 
    - `authentication_state`. [`AWAITING` | `STARTED` | `REQUESTED` | `APPROVED` | `DENIED`]. Current authentication state.
    - `of_dpid`. OLT Openflow ID.
    - `uni_port_id`. ONU UNI Port ID.
    - `admin_onu_state`. [`AWAITING` | `ENABLED` | `DISABLED`]. ONU administrative state.
    - `status_message`. Status text of current state machine state.
    - `pppoe_state`. [`AWAITING` | `INITIATED` | `CONNECTED` | `DISCONNECTED`]. Status of the subscriber PPPoE session.
    - `pppoe_session_id`. Subscriber PPPoE session ID.
    - `ipcp_state`. [`AWAITING` | `CONF_ACK` | `CONF_REQUEST`]. Status of the IPCP protocol for IP address assignment.
    - `ip_address`. Subscriber ip address.
    - `mac_address`. Subscriber mac address.
    - `oper_onu_status`. [`AWAITING` | `ENABLED` | `DISABLED`]. ONU operational state.
- `DtWorkflowDriverWhiteListEntry`. This model holds a whitelist authorizing an ONU with a specific serial number to be connected to a specific PON Port on a specific OLT.
    - `owner`. Relation to the DtWorkflowDriverService that owns this whitelist entry.
    - `serial_number`. Serial number of ONU.
    - `pon_port_id`. PON port identifier.
    - `device_id`. OLT device identifier.

## Example Tosca - Create a whitelist entry

```yaml
tosca_definitions_version: tosca_simple_yaml_1_0
imports:
  - custom_types/dtworkflowdriverwhitelistentry.yaml
  - custom_types/dtworkflowdriverservice.yaml
description: Create an entry in the whitelist
topology_template:
  node_templates:

    service#dtworkflow:
      type: tosca.nodes.DtWorkflowDriverService
      properties:
        name: dt-workflow-driver
        must-exist: true

    whitelist:
      type: tosca.nodes.DtWorkflowDriverWhiteListEntry
      properties:
        serial_number: BRCM22222222
        pon_port_id: 536870912
        device_id: of:000000000a5a0072
      requirements:
        - owner:
            node: service#dtworkflow
            relationship: tosca.relationships.BelongsToOne
```

## Integration with other Services

This service integrates closely with the `R-CORD` and `vOLT` services, directly manipulating models (`RCORDSubscriber`, `ONUDevice`) in those services.

## Synchronizer Workflows

This synchronizer implements only event_steps and model_policies. It's job is to listen for events and execute a state machine associated with those events. Service Instances are created automatically when ONU events are received. As the state machine changes various states for authentication, etc., those changes will be propagated to the appropriate objects in the `R-CORD` and `vOLT` services.

The state machine is described below.

### Service Instances State Machine

TODO: add the info with `bng.pppoe` events

### Model Policy: DtWorkflowDriverServiceInstancePolicy

This model policy is responsible for reacting to state changes that are caused by various event steps, implementing the state machine described above.

### Event Step: ONUEventStep

Listens on `onu.events` and updates the `onu_state` of `DtWorkflowDriverServiceInstance`. Also resets `authentication_state` when an ONU is disabled. Automatically creates `DtWorkflowDriverServiceInstance` as necessary.

## Events format

This events are generated by various applications running on top of ONOS and published on a Kafka bus.
Here is the structure of the events and their topics.

### onu.events

```json
{
  "timestamp": "2018-09-11T01:00:49.506Z",
  "status": "activated", // or disabled
  "serialNumber": "ALPHe3d1cfde", // ONU serial number
  "portNumber": "16", // uni port
  "deviceId": "of:000000000a5a0072" // OLT OpenFlow Id
}
```

### bng.pppoe
This type of event regards all the possible events that the BNG ONOS app can generate for the PPPoE protocol.
The different type of events are identified via `messageType` field.

```json
{
  "timestamp": "2019-10-07T00:41:47.483Z",
  "eventType" : "IPCP_CONF_ACK",
  "deviceId" : "of:000000000a5a0072",
  "portNumber" : "16",
  "serialNumber": "ALPHe3d1cfde", // ONU serial number
  "sessionId": "32", // PPPoE Session ID
  "ipAddress": "10.255.255.100",
  "macAddress": "00:11:22:33:44:55"
}
```
