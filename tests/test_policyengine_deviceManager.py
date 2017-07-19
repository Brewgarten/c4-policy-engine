import logging

import pytest

from c4.devices.policyengine import PolicyEngineManager
from c4.messaging import Router, RouterClient
from c4.system.configuration import States, Roles
from c4.system.deviceManager import DeviceManager
from c4.system.messages import (LocalStartDeviceManager, LocalStopDeviceManager,
                                Status)


log = logging.getLogger(__name__)

pytestmark = pytest.mark.usefixtures("temporaryIPCPath")

@pytest.fixture
def systemManagerClusterInfo(backend):
    return backend.ClusterInfo("test", "ipc://test.ipc", "ipc://test.ipc", Roles.ACTIVE, States.RUNNING)

class TestPolicyEngineManager(object):

    def test_getOperations(self):

        operations = PolicyEngineManager.getOperations()
        assert {"setPolicies", "start", "stop"} == set(operations.keys())

    def test_status(self, systemManagerClusterInfo):

        router = Router("test")  # @UnusedVariable

        deviceManager = DeviceManager(systemManagerClusterInfo, "policyengine", PolicyEngineManager)
        assert deviceManager.start()

        client = RouterClient("test/policyengine")
        startResponse = client.sendRequest(LocalStartDeviceManager("test", "test/policyengine"))

        statuses = []
        for _ in range(3):
            statuses.append(client.sendRequest(Status("test/policyengine")))

        stopResponse = client.sendRequest(LocalStopDeviceManager("test", "test/policyengine"))

        assert deviceManager.stop()

        assert startResponse["state"] == States.RUNNING
        assert stopResponse["state"] == States.REGISTERED
