from c4.policyengine import Policy
from c4.policyengine.actions.actions import Start
from c4.system.backend import Backend
from c4.system.configuration import States
from c4.system.deviceManager import ConfiguredDeviceManagerStatus
from c4.utils.logutil import ClassLogger

@ClassLogger
class ConfiguredDeviceManagerPolicy(Policy):
    """
    Policy to check the status of a services managed by ConfiguredDeviceManagerImplementation
    and perform HA actions.

    :param cache: cache
    :type cache: :class:`~c4.policyengine.Cache`
    """
    id = "devices.configured.start"

    def __init__(self, cache):
        super(ConfiguredDeviceManagerPolicy, self).__init__(cache)
        self.devicesToStart = []

    def evaluateEvent(self):
        """
        Check the status of the device
        """
        deviceHistory = Backend().deviceHistory
        self.devicesToStart = []
        for node, deviceName in self.getEnabledDevices():
            entry = deviceHistory.getLatest(node, deviceName)
            if entry:
                currentStatus = entry.status
                if currentStatus.state == States.RUNNING and currentStatus.status != ConfiguredDeviceManagerStatus.OK:
                    self.devicesToStart.append((node, deviceName))

        return len(self.devicesToStart) > 0

    def getEnabledDevices(self):
        """
        Get ConfiguredDeviceManagerImplementation devices that are enabled.
        Filtering is done by what is provided in platform settings in the configuration.
        - If configuredPoliciesEnabled list exists in settings and contains values, use this to determine enabled devices.
            - If it exists and is empty, consider all devices enabled
            - If it doesn't exist and configuredPoliciesDisabled list exists, use that to determine which devices are disabled.
            - If neither list exists, consider all devices enabled.
        """
        enabledDevices = []
        configuration = Backend().configuration
        enabledList = None
        disabledList = []
        settings = configuration.getPlatform().settings
        if settings.has_key("configuredPoliciesEnabled"):
            enabledList = settings["configuredPoliciesEnabled"]
        if settings.has_key("configuredPoliciesDisabled"):
            disabledList = settings["configuredPoliciesDisabled"]

        for node in configuration.getNodeNames():
            for deviceName in configuration.getDevices(node, flatDeviceHierarchy=True):
                deviceInfo= configuration.getDevice(node, deviceName)
                if deviceInfo.type == "c4.system.deviceManager.ConfiguredDeviceManagerImplementation":
                    if enabledList:
                        if len(enabledList) == 0 or \
                           deviceName in enabledList or \
                           "{}/{}".format(node, deviceName) in enabledList:
                            enabledDevices.append((node, deviceName))
                    elif deviceName not in disabledList and "{}/{}".format(node, deviceName) not in disabledList:
                        enabledDevices.append((node, deviceName))

        return enabledDevices

    def performActions(self):
        """
        Send start messages to the DMs with failed statuses
        """
        for node, deviceName in self.devicesToStart:
            self.log.info("Performing failure recovery on %s/%s", node, deviceName)
            Start().perform(node, deviceName)