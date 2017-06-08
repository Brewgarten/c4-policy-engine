"""
Generic policy actions
"""
import socket

from c4.messaging import RouterClient
from c4.policyengine import Action
from c4.system.messages import Operation

class Start(Action):
    """
    Sends a start message to a device
    """

    id = "devices.Start"

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

        self.log.debug("sending start request to %s/%s", node, fullDeviceName)
        client.forwardMessage(Operation("{0}/{1}".format(node, fullDeviceName), "start"))
        return True