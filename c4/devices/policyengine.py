"""
Policy engine device manager
"""
import logging

from c4.policyengine import PolicyEngineProcess
from c4.system.deviceManager import (DeviceManagerImplementation, 
                                     DeviceManagerStatus,
                                     operation)
from c4.utils.logutil import ClassLogger


log = logging.getLogger(__name__)

@ClassLogger
class PolicyEngineManager(DeviceManagerImplementation):
    """
    Policy engine manager
    """
    def __init__(self, clusterInfo, name, properties=None):
        super(PolicyEngineManager, self).__init__(clusterInfo, name, properties=properties)
        self.policyEngineProcess = None
        if not properties:
            self.properties = {}
        self.properties['node'] = self.node
        self.properties['name'] = name

    def handleLocalStartDeviceManager(self, message, envelope):
        """
        Handle :class:`~c4.system.messages.LocalStartDeviceManager` messages

        :param message: message
        :type message: dict
        :param envelope: envelope
        :type envelope: :class:`~c4.system.messages.Envelope`
        """
        self.start()
        return super(PolicyEngineManager, self).handleLocalStartDeviceManager(message, envelope)

    def handleLocalStopDeviceManager(self, message, envelope):
        """
        Handle :class:`~c4.system.messages.LocalStopDeviceManager` messages

        :param message: message
        :type message: dict
        :param envelope: envelope
        :type envelope: :class:`~c4.system.messages.Envelope`
        """
        self.stop()
        return super(PolicyEngineManager, self).handleLocalStopDeviceManager(message, envelope)

    def handleStatus(self, message):
        """
        The handler for an incoming Status message.
        """
        return PolicyEngineStatus(self.state, self.properties)

    @operation
    def setPolicies(self, policies):
        if policies:
            self.properties['policies'] = policies
            
    @operation
    def start(self):
        """
        Start policy engine process
        """
        if self.policyEngineProcess and self.policyEngineProcess.is_alive():
            self.log.error("policy engine process already started")
        else:
            self.policyEngineProcess = PolicyEngineProcess(properties=self.properties)
            self.policyEngineProcess.start()

    @operation
    def stop(self):
        """
        Stop policy engine process
        """
        if self.policyEngineProcess and self.policyEngineProcess.is_alive():
            self.policyEngineProcess.terminate()
            self.policyEngineProcess.join()
            self.policyEngineProcess = None

class PolicyEngineStatus(DeviceManagerStatus):
    """
    Policy engine device manager status

    :param state: state
    :type state: :class:`~c4.system.configuration.States`
    :param properties: properties
    :type properties: dict
    """
    def __init__(self, state, properties):
        super(PolicyEngineStatus, self).__init__()
        self.state = state
        if properties and "policies" in properties:
            self.policies = properties['policies']
