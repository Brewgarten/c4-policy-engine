import logging
import random
import sys

from pyparsing import ParseException, ParseFatalException
import pytest

from c4.policyengine import (Action, ActionReference,
                             Event,
                             Policy, PolicyComponent, PolicyDatabase, PolicyEngine)
from c4.policyengine.events.operators.boolean import And, Not, Or
from c4.policyengine.events.operators.comparison import Equal, GreaterThan, GreaterThanOrEqual, LessThan, LessThanOrEqual
from c4.system.configuration import States, NodeInfo, Roles
from c4.utils.util import getModuleClasses, getFullModuleName


log = logging.getLogger(__name__)
logging.basicConfig(format='%(asctime)s [%(levelname)s] <%(processName)s> [%(name)s(%(filename)s:%(lineno)d)] - %(message)s', level=logging.DEBUG)
logging.getLogger("c4.policyengine").setLevel(logging.INFO)
logging.getLogger("c4.policyengine.PolicyEngine").setLevel(logging.INFO)

@pytest.fixture(scope="module")
def testEventsAndActions():
    """
    Add all test events and actions to the built-in events and actions
    """
    currentModule = sys.modules[getFullModuleName(Alert)]

    # add all test events
    import c4.policyengine.events
    eventClasses = getModuleClasses(currentModule, Event)
    for eventClass in eventClasses:
        eventClass.__module__ = c4.policyengine.events.__name__
        setattr(c4.policyengine.events, eventClass.__name__, eventClass)

    # add all test actions
    import c4.policyengine.actions
    actionClasses = getModuleClasses(currentModule, Action)
    for actionClass in actionClasses:
        actionClass.__module__ = c4.policyengine.actions.__name__
        setattr(c4.policyengine.actions, actionClass.__name__, actionClass)

pytestmark = pytest.mark.usefixtures("testEventsAndActions")

@pytest.fixture
def policyEngine(backend):

    configuration = backend.configuration
    configuration.addNode(NodeInfo("node1", "tcp://1.2.3.4:5000", role=Roles.ACTIVE))
    configuration.addAlias("system-manager", "node1")
    properties = {
        "policy.timer.initial": 5,
        "policy.timer.interval": 10,
        "policies": [ 
            "device.status.refresh",
            "node.status.refresh"
        ],
        "performance.warning.threshold": 2
    }

    return PolicyEngine(properties=properties)

class Alert(Action):

    id = "test.system.alert"

    def perform(self, string1, string2):
        log.debug("'%s' '%s' and '%s'", self.id, string1, string2)
        return True

class FreeDiskSpace(Event):

    id = "test.diskspace.free"

    def evaluate(self):
        return 1000

class Email(Action):

    id = "test.system.email"

    def perform(self, message, to='home@example.org',subject='test email'):
        log.debug("'%s' '%s' with subject '%s' and content '%s')", self.id, to, subject, message)
        return True

class Healthy(Event):

    id = "test.healthy"

    def evaluate(self):
        return True

class KeyValueTestEvent(Event):

    id = "test.keyValue"

    def evaluate(self, a="a", b="b"):
        return [a, b]

# this is an event for testing purposes
# in general this should probably be an operator
class Length(Event):

    id = "test.len"

    def evaluate(self, l):
        return len(l)

class Log(Action):

    id = "test.system.log"

    def perform(self, string):
        log.debug("'%s' '%s'", self.id, string)
        return True

class NodeState(Event):

    id = "test.nodes.state"

    def evaluate(self, *nodes):
        return [States.REGISTERED] * len(nodes)

class RandomUtilization(Event):

    id = "test.random.utilization"

    def evaluate(self):
        return random.random()

class Utilization(Event):

    id = "test.utilization"

    def evaluate(self):
        return 0.75

class LowUtilization(Policy):

    id = "test.utilization.low"

    def evaluateEvent(self):
        return False

    def performActions(self):
        pass

class HighUtilization(PolicyComponent):

    def __init__(self):
        super(HighUtilization, self).__init__(
            "test.utilization.high",
            GreaterThan(Utilization(), 0.7),
            [ActionReference(Log, ["high utilization"])])

def test_boolean():

    assert And(True, None).value == False
    assert And(1 != 2, 1==1).value == True

    assert Not(True).value == False
    assert Not(1 != 1).value == True

    assert Or(False, True).value == True
    assert Or(False, None).value == False

def test_comparison():

    assert Equal(1, 1).value == True
    assert Equal(2, "two").value == False
    assert Equal(2, "2").value == False

    assert LessThan(1, 2).value == True
    assert LessThan(1, "test").value == False
    assert LessThan("b", "a").value == False

    assert LessThanOrEqual(1, 1).value == True
    assert LessThanOrEqual(1, "test").value == False
    assert LessThanOrEqual("a", "ab").value == True

    assert GreaterThan(2, 1).value == True
    assert GreaterThan("test", 1).value == False
    assert GreaterThan("a", "b").value == False

    assert GreaterThanOrEqual(1, 1).value == True
    assert GreaterThanOrEqual("test", 1).value == False
    assert GreaterThanOrEqual("ab", "a").value == True


def test_caching(policyEngine):

    event = policyEngine.policyParser.parseEvent("(test.random.utilization > 1.0) or (test.random.utilization > 1.0)")
    policyEngine.cache.enabled = False
    assert event.one.one.evaluate() != event.two.one.evaluate()
    policyEngine.cache.enabled = True
    assert event.one.one.evaluate() == event.two.one.evaluate()
    policyEngine.cache.enabled = False

def test_combination():

    assert GreaterThan(Utilization(), 0.9).value == False
    assert And(GreaterThan(Utilization(), 0.5), LessThanOrEqual(FreeDiskSpace(), 2500)).value == True

def test_parsing(policyEngine):

    assert policyEngine.policyParser.parseEvent("test.healthy").value == True
    assert policyEngine.policyParser.parseEvent("not test.healthy").value == False
    assert policyEngine.policyParser.parseEvent("(not test.healthy)").value == False
    assert policyEngine.policyParser.parseEvent("not (not test.healthy)").value == True
    assert policyEngine.policyParser.parseEvent("test.utilization >= 0.9").value == False
    assert policyEngine.policyParser.parseEvent("(test.utilization >= 0.9) and (test.diskspace.free < 2500)").value == False
    assert policyEngine.policyParser.parseEvent("(test.utilization >= 0.9) or (test.diskspace.free < 2500)").value == True
    assert policyEngine.policyParser.parseEvent("(test.utilization >= 0.9) and test.healthy").value == False
    assert policyEngine.policyParser.parseEvent("not (( test.utilization >= 0.9) and not test.healthy)").value == True

    # Note that this will cause multiple paths to match because of the way the grammar is defined
    assert policyEngine.policyParser.parseEvent("test.nodes.state('rack1-master1', 'rack1-master2')").value == [States.REGISTERED, States.REGISTERED]
    assert policyEngine.policyParser.parseEvent("test.len(test.nodes.state('rack1-master1', 'rack1-master2')) >= 1").value == True
    assert policyEngine.policyParser.parseEvent("test.keyValue(a='testA', b='testB')").value == ["testA", "testB"]

    with pytest.raises(ParseException):
        policyEngine.policyParser.parseEvent("(test.utilization >= 0.9) and test.healthy or (test.diskspace.free < 2500)")
    with pytest.raises(ParseException):
        policyEngine.policyParser.parseEvent("not")

    assert policyEngine.policyParser.parseAction("test.system.log(\"test\")").perform()
    assert policyEngine.policyParser.parseAction("""test.system.email('some important information',
                                        to='sysadmin@example.org',subject='server is down!')""").perform()
    assert policyEngine.policyParser.parseAction("""test.system.email(to='sysadmin@example.org',
                                        'some important information',
                                        subject='server is down!')""").perform()
    actions = policyEngine.policyParser.parseActions("test.system.log('test'),   test.system.alert('important error','very very important')")
    for action in actions:
        assert action.perform()

    assert policyEngine.policyParser.parseAction("test.system.alert('event value', test.utilization)").perform()

    with pytest.raises(ParseFatalException):
        policyEngine.policyParser.parseAction("test.system.log()")
    with pytest.raises(ParseFatalException):
        policyEngine.policyParser.parseAction("test.system.log('test', test='test')")

    policyEngine.policyParser.parsePolicy("system.healthy: test.healthy -> test.system.log('system healthy')")
    policyEngine.policyParser.parsePolicy("system.healthy: test.healthy -> test.system.log('system healthy'), test.system.alert('system is', test.healthy)")

def test_policyEngine(policyEngine):

    numberOfPolicies = len(policyEngine.policies)
    # TODO: add assertable actions
    # TODO: add mix of enabled and disabled policies
    policyEngine.loadPolicy("test.system.healthy: test.healthy -> test.system.log('system healthy')")
    assert len(policyEngine.policies) == numberOfPolicies + 1
    policyEngine.loadPolicy("test.the_same_system.healthy : test.healthy    ->     test.system.log('system healthy')")
    assert len(policyEngine.policies) == numberOfPolicies + 2
    policyEngine.loadPolicy("test.system.nothealthy:not test.healthy -> test.system.log('system is not healthy')")
    assert len(policyEngine.policies) == numberOfPolicies + 3

    policyEngine.run()

def test_policyEngineLoading(policyEngine):
    import json
    numberOfPolicies = len(policyEngine.policies)
    assert numberOfPolicies > 0

    policy = policyEngine.policyParser.parsePolicy("test.diskspace.low: (test.diskspace.free <= 100) -> test.system.log('Disk space is low'),test.system.log('Disk space is low')")
    assert policy.id == "test.diskspace.low"
    policyEngine.addPolicy(policy)
    propertiesString = """{
    "policy.timer.initial": 5,
    "policy.timer.interval": 10,
    "include.policies.database": true,
    "policies": [ 
        "device.status.refresh",
        "node.status.refresh",
        "test.diskspace.low"
    ],
    "performance.warning.threshold": 2
}"""
    properties = json.loads(propertiesString)

    policyEngine2 = PolicyEngine(properties=properties)
    assert "test.diskspace.low" in policyEngine2.policies
    assert len(policyEngine2.policies) == numberOfPolicies + 1

    properties = {
        "policy.timer.initial": 5,
        "policy.timer.interval": 10,
        "include.policies.database": False,
        "policies": [ 
            "device.status.refresh",
            "node.status.refresh",
            "test.diskspace.low"
        ],
        "performance.warning.threshold": 2
    }

    policyEngine3 = PolicyEngine(properties=properties)
    assert "test.diskspace.low" not in policyEngine3.policies
    assert len(policyEngine3.policies) == numberOfPolicies

class TestPolicyDatabase():

    def test_addPolicyUsingName(self, backend):

        policyDatabase = PolicyDatabase()

        lowUtilization = LowUtilization()
        assert policyDatabase.addPolicyUsingName(lowUtilization.id, lowUtilization)
        # TODO: adjust to True once parent child relations have been implemented
        assert not policyDatabase.addPolicyUsingName(lowUtilization.id + "/" + lowUtilization.id, LowUtilization())

    def test_addPolicy(self, backend):

        policyDatabase = PolicyDatabase()

        lowUtilization = LowUtilization()
        policyDatabase.addPolicy(lowUtilization)
        assert policyDatabase.policyExists(lowUtilization.id)

        highUtilization = HighUtilization()
        policyDatabase.addPolicy(HighUtilization())
        assert policyDatabase.policyExists(highUtilization.id)

    def test_clear(self, backend):

        policyDatabase = PolicyDatabase()

        policyDatabase.addPolicy(LowUtilization())
        policyDatabase.addPolicy(HighUtilization())
        policyDatabase.clear()

        assert policyDatabase.getNumberOfTopLevelPolicies() == 0

    def test_disablePolicy(self, backend):

        policyDatabase = PolicyDatabase()

        from c4.policyengine import States as PolicyStates

        lowUtilization = LowUtilization()
        policyDatabase.addPolicy(lowUtilization)
        policyDatabase.disablePolicy(lowUtilization.id)
        assert policyDatabase.getPolicyState(lowUtilization.id) == PolicyStates.DISABLED

        highUtilization = HighUtilization()
        policyDatabase.addPolicy(highUtilization)
        policyDatabase.disablePolicy(highUtilization.id)
        assert policyDatabase.getPolicyState(highUtilization.id) == PolicyStates.DISABLED

    def test_enablePolicy(self, backend):

        policyDatabase = PolicyDatabase()

        from c4.policyengine import States as PolicyStates

        lowUtilization = LowUtilization()
        lowUtilization.state = PolicyStates.DISABLED
        policyDatabase.addPolicy(lowUtilization)
        lowUtilization.state = PolicyStates.ENABLED
        policyDatabase.enablePolicy(lowUtilization.id)
        assert policyDatabase.getPolicyState(lowUtilization.id) == PolicyStates.ENABLED

        highUtilization = HighUtilization()
        highUtilization.state = PolicyStates.DISABLED
        policyDatabase.addPolicy(highUtilization)
        highUtilization.state = PolicyStates.ENABLED
        policyDatabase.enablePolicy(highUtilization.id)
        assert policyDatabase.getPolicyState(highUtilization.id) == PolicyStates.ENABLED

    def test_getNumberOfTopLevelPolicies(self, backend):

        policyDatabase = PolicyDatabase()

        policyDatabase.addPolicy(LowUtilization())
        policyDatabase.addPolicy(HighUtilization())

        assert policyDatabase.getNumberOfTopLevelPolicies() == 2

    def test_getPolicyInfos(self, backend):

        policyDatabase = PolicyDatabase()

        policyImplementation = LowUtilization()
        policyDatabase.addPolicy(policyImplementation)

        policyComponent = HighUtilization()
        policyDatabase.addPolicy(policyComponent)

        assert set(policy.name for policy in policyDatabase.getPolicyInfos()) == set([policyImplementation.id, policyComponent.id])

    def test_getPolicyState(self, backend):

        policyDatabase = PolicyDatabase()

        lowUtilization = LowUtilization()
        policyDatabase.addPolicy(lowUtilization)
        from c4.policyengine import States as PolicyStates
        assert policyDatabase.getPolicyState(lowUtilization.id) == PolicyStates.ENABLED

    def test_policyExists(self, backend):

        policyDatabase = PolicyDatabase()

        lowUtilization = LowUtilization()
        policyDatabase.addPolicy(lowUtilization)
        assert policyDatabase.policyExists(lowUtilization.id)

        highUtilization = HighUtilization()
        policyDatabase.addPolicy(highUtilization)
        assert policyDatabase.policyExists(highUtilization.id)
