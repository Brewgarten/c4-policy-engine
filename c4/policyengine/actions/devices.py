"""
Generic policy actions
"""
import socket

from c4.messaging import RouterClient
from c4.policyengine import Action
from c4.system.backend import Backend
from c4.system.messages import Operation
from c4.utils.logutil import ClassLogger

@ClassLogger
class Start(Action):
    """
    Sends a start message to a device
    """

    id = "devices.start"

    def perform(self, node, fullDeviceName):
        """
        Sends a start message to a device

        :param node: node name
        :type node: str
        :param fullDeviceName: fully qualified device manager name
        :type fullDeviceName: device
        """
        address = socket.gethostname().split(".")[0]
        client = RouterClient(address)

        self.log.debug("Sending start request to %s/%s", node, fullDeviceName)
        client.forwardMessage(Operation("{0}/{1}".format(node, fullDeviceName), "start"))
        return True

@ClassLogger
class Restart(Action):
    """
    Sends a restart message to a device
    """

    id = "devices.restart"

    def perform(self, node, fullDeviceName):
        """
        Sends a restart message to a device

        :param node: node name
        :type node: str
        :param fullDeviceName: fully qualified device manager name
        :type fullDeviceName: device
        """
        address = socket.gethostname().split(".")[0]
        client = RouterClient(address)
        configuration = Backend().configuration
        resolvedNode = node
        if node not in configuration.getNodeNames():
            resolvedNode = configuration.getAliases().get(node, None)

        if not resolvedNode:
            self.log.error("Could not resolve node address for %s", node)
            return False

        self.log.debug("Sending restart request to %s/%s", resolvedNode, fullDeviceName)
        client.forwardMessage(Operation("{0}/{1}".format(resolvedNode, fullDeviceName), "restart"))
        return True