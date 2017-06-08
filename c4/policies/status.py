"""
This library contains status related policy functionality

Examples
--------

.. code-block:: python

    device.status.ageInSeconds('rack1-master1', 'cpu') >= 10 -> system.requestStatus('rack1-master1', 'cpu')

Functionality
-------------
"""
import datetime
import logging
import socket

from c4.messaging import RouterClient
from c4.policyengine import Action, Event, Policy
from c4.system.backend import Backend
from c4.system.configuration import Roles, States
from c4.system.messages import Status
from c4.utils.logutil import ClassLogger



log = logging.getLogger(__name__)

@ClassLogger
class StatusAgeInSeconds(Event):
    """
    Status age of a device or system manager in seconds
    """
    id = "device.status.ageInSeconds"

    def evaluate(self, node, fullDeviceName=None):
        """
        Retrieve the age of the specified device or system manager in seconds

        :param node: node name
        :type node: str
        :param fullDeviceName: fully qualified device manager name
        :type fullDeviceName: device
        """
        if fullDeviceName:
            status = Backend().deviceHistory.getLatest(node, fullDeviceName)
        else:
            status = Backend().nodeHistory.getLatest(node)

        if status is None:
            return -1

        now = datetime.datetime.utcnow()
        timeDifference = now - status.timestamp
        return (timeDifference.days * 3600 * 24) + timeDifference.seconds

@ClassLogger
class RequestStatus(Action):
    """
    Send status message to a device or system manager
    """
    id = "system.requestStatus"

    def perform(self, node, fullDeviceName=None):
        """
        Send status message to the specified device or system manager

        :param node: node name
        :type node: str
        :param fullDeviceName: fully qualified device manager name
        :type fullDeviceName: device
        """
        address = socket.gethostname().split(".")[0]
        client = RouterClient(address)

        # FIXME: need to convert fullDeviceName . to / for routing
        if fullDeviceName:
            self.log.debug("sending status request to %s/%s", node, fullDeviceName)
            client.forwardMessage(Status("{0}/{1}".format(node, fullDeviceName)))
        else:
            self.log.debug("sending status request to %s", node)
            client.forwardMessage(Status(node))

        return True

@ClassLogger
class DeviceManagerStatusRefreshPolicy(Policy):
    """
    Policy that sends out status request messages to device managers
    according to their specified status interval

    :param cache: cache
    :type cache: :class:`~c4.policyengine.Cache`
    """
    id = "device.status.refresh"

    def __init__(self, cache):
        super(DeviceManagerStatusRefreshPolicy, self).__init__(cache)
        self.requestDeviceMap = {}

    def evaluateEvent(self):
        """
        Check status age for all running device managers
        """
        configuration = Backend().configuration
        policySettings = configuration.getPlatform().settings.get("policies", {}).get(self.id, {})

        statusAgeInSeconds = StatusAgeInSeconds()

        self.requestDeviceMap.clear()
        statusRequestNeeded = False
        for node in configuration.getNodeNames():

            nodeInfo = configuration.getNode(node, includeDevices=True, flatDeviceHierarchy=True)

            if nodeInfo.state == States.RUNNING:

                self.requestDeviceMap[node] = set()

                for fullDeviceName, deviceInfo in nodeInfo.devices.items():

                    age = statusAgeInSeconds.evaluate(node, fullDeviceName)
                    # note that all the intervals are specified in seconds
                    statusInterval = policySettings.get(deviceInfo.type, 10)

                    if age < 0 or age >= statusInterval:
                        self.log.debug("%s/%s: age %ss >= %ss", node, fullDeviceName, age, statusInterval)
                        self.requestDeviceMap[node].add(fullDeviceName)
                        statusRequestNeeded = True
                    else:
                        self.log.debug("%s/%s: age %ss < %ss", node, fullDeviceName, age, statusInterval)

        return statusRequestNeeded

    def performActions(self):
        """
        Send out status request messages to device managers
        that have been identified as having an old status
        """
        requestStatus = RequestStatus()
        for node, devices in self.requestDeviceMap.items():
            for fullDeviceName in devices:
                requestStatus.perform(node, fullDeviceName)

@ClassLogger
class SystemManagerStatusRefreshPolicy(Policy):
    """
    Policy that sends out status request messages to system managers
    according to their specified status interval

    :param cache: cache
    :type cache: :class:`~c4.policyengine.Cache`
    """
    id = "node.status.refresh"

    def __init__(self, cache):
        super(SystemManagerStatusRefreshPolicy, self).__init__(cache)
        self.requestNodes = set()

    def evaluateEvent(self):
        """
        Check status age for all running system managers
        """
        configuration = Backend().configuration
        policySettings = configuration.getPlatform().settings.get("policies", {}).get(self.id, {})
        # note that all the intervals are specified in seconds
        statusIntervalParameters = {
            Roles.ACTIVE: policySettings.get("interval.active", 5),
            Roles.PASSIVE: policySettings.get("interval.passive", 5),
            Roles.THIN: policySettings.get("interval.thin", 10),
        }

        statusAgeInSeconds = StatusAgeInSeconds()

        self.requestNodes.clear()
        statusRequestNeeded = False
        for node in configuration.getNodeNames():

            nodeInfo = configuration.getNode(node, includeDevices=False)

            if nodeInfo.state == States.RUNNING:

                age = statusAgeInSeconds.evaluate(node)
                # note that all the intervals are specified in seconds
                statusInterval = statusIntervalParameters.get(nodeInfo.role, 10)

                if age < 0 or age >= statusInterval:
                    self.log.debug("%s: age %ss >= %ss", node, age, statusInterval)
                    self.requestNodes.add(node)
                    statusRequestNeeded = True
                else:
                    self.log.debug("%s: age %ss < %ss", node, age, statusInterval)

        return statusRequestNeeded

    def performActions(self):
        """
        Send out status request messages to system managers
        that have been identified as having an old status
        """
        requestStatus = RequestStatus()
        for node in self.requestNodes:
            requestStatus.perform(node)
