import logging
import pytest

from c4.system.configuration import DeviceInfo, DeviceManagerConfiguration, States
from c4.system.deviceManager import ConfiguredDeviceManagerStatus
from c4.policyengine.policyEngine import Cache
from c4.policies.configuredDeviceManagerPolicy import ConfiguredDeviceManagerPolicy
from c4.system.configuration import NodeInfo

log = logging.getLogger(__name__)

@pytest.fixture
def policy():
    return ConfiguredDeviceManagerPolicy(Cache())

@pytest.fixture
def configuredBackend(backend):
    backend.configuration.addNode(NodeInfo("node1", ""))
    dmConfig = DeviceManagerConfiguration("/usr/bin/myService start", "/usr/bin/myService status", "/usr/bin/myService stop", rc=0)
    deviceInfo = DeviceInfo("myservice", "c4.system.deviceManager.ConfiguredDeviceManagerImplementation", state=States.RUNNING)
    deviceInfo.properties = {"configuration": dmConfig}
    backend.configuration.addDevice("node1", "myservice", deviceInfo)

    return backend

class TestConfiguredDeviceManagerPolicy(object):
    def test_neg_evaluateEvent_OKstatus(self, configuredBackend, policy):
        history = configuredBackend.deviceHistory
        history.add("node1", "myservice", ConfiguredDeviceManagerStatus(States.RUNNING, ConfiguredDeviceManagerStatus.OK))
        assert not policy.evaluateEvent()

    def test_neg_evaluateEvent_notRunning(self, configuredBackend, policy):
        history = configuredBackend.deviceHistory
        history.add("node1", "myservice", ConfiguredDeviceManagerStatus(States.REGISTERED, ConfiguredDeviceManagerStatus.OK))
        assert not policy.evaluateEvent()

    def test_neg_evaluateEvent_noStatus(self, configuredBackend, policy):
        assert not policy.evaluateEvent()

    def test_pos_evaluateEvent(self, configuredBackend, policy):
        history = configuredBackend.deviceHistory
        history.add("node1", "myservice", ConfiguredDeviceManagerStatus(States.RUNNING, ConfiguredDeviceManagerStatus.FAILED))
        assert policy.evaluateEvent()

    def test_getEnabledDevices_disabled(self, configuredBackend, policy):
        platform = configuredBackend.configuration.getPlatform()
        platform.settings["configuredPoliciesDisabled"] = ["myservice"]
        configuredBackend.configuration.addPlatform(platform)
        assert policy.getEnabledDevices() == []

    def test_getEnabledDevices_disabled_withNode(self, configuredBackend, policy):
        platform = configuredBackend.configuration.getPlatform()
        platform.settings["configuredPoliciesDisabled"] = ["node1/myservice"]
        configuredBackend.configuration.addPlatform(platform)
        assert policy.getEnabledDevices() == []

    def test_getEnabledDevices_enabled(self, configuredBackend, policy):
        assert policy.getEnabledDevices() == [("node1", "myservice")]

    def test_getEnabledDevices_enabled_emptyList(self, configuredBackend, policy):
        platform = configuredBackend.configuration.getPlatform()
        platform.settings["configuredPoliciesEnabled"] = []
        configuredBackend.configuration.addPlatform(platform)
        assert policy.getEnabledDevices() == [("node1", "myservice")]

    def test_getEnabledDevices_enabled_list(self, configuredBackend, policy):
        platform = configuredBackend.configuration.getPlatform()
        platform.settings["configuredPoliciesEnabled"] = ["myservice"]
        configuredBackend.configuration.addPlatform(platform)
        assert policy.getEnabledDevices() == [("node1", "myservice")]

    def test_getEnabledDevices_enabled_list_withNode(self, configuredBackend, policy):
        platform = configuredBackend.configuration.getPlatform()
        platform.settings["configuredPoliciesEnabled"] = ["node1/myservice"]
        configuredBackend.configuration.addPlatform(platform)
        assert policy.getEnabledDevices() == [("node1", "myservice")]

    def test_getEnabledDevices_extraDevice(self, configuredBackend, policy):
        deviceInfo = DeviceInfo("status", "c4.devices.policyengine.PolicyEngineManager", state=States.RUNNING)
        configuredBackend.configuration.addDevice("node1", "policyengine", deviceInfo)

        assert policy.getEnabledDevices() == [("node1", "myservice")]