import logging
import pytest
import random
import sys

from pyparsing import ParseException, ParseFatalException

from c4.system.configuration import States
from c4.policyengine import Action, ActionReference, Event, PolicyEngine, PolicyComponent
from c4.policyengine.events.operators.boolean import And, Not, Or
from c4.policyengine.events.operators.comparison import Equal, GreaterThan, GreaterThanOrEqual, LessThan, LessThanOrEqual
from c4.utils.util import getModuleClasses, getFullModuleName

log = logging.getLogger(__name__)
logging.basicConfig(format='%(asctime)s [%(levelname)s] <%(processName)s> [%(name)s(%(filename)s:%(lineno)d)] - %(message)s', level=logging.DEBUG)
logging.getLogger("c4.system.db").setLevel(logging.INFO)
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

def test_caching(temporaryDatabasePaths):

    policyEngine = PolicyEngine()

    event = policyEngine.policyParser.parseEvent("(test.random.utilization > 1.0) or (test.random.utilization > 1.0)")
    policyEngine.cache.enabled = False
    assert event.one.one.evaluate() != event.two.one.evaluate()
    policyEngine.cache.enabled = True
    assert event.one.one.evaluate() == event.two.one.evaluate()
    policyEngine.cache.enabled = False

def test_combination():

    assert GreaterThan(Utilization(), 0.9).value == False
    assert And(GreaterThan(Utilization(), 0.5), LessThanOrEqual(FreeDiskSpace(), 2500)).value == True

def test_parsing(temporaryDatabasePaths):

    policyEngine = PolicyEngine()

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

def test_policyEngine(temporaryDatabasePaths):

    policyEngine = PolicyEngine()

    numberOfPolicies = len(policyEngine.policies)
    # TODO: add assertable actions
    # TODO: add mix of enabled and disabled policies
    policyEngine.loadPolicy("test.system.healthy: test.healthy -> test.system.log('system healthy')")
    assert len(policyEngine.policies) == numberOfPolicies + 1
    policyEngine.loadPolicy("test.the_same_system.healthy : test.healthy    ->     test.system.log('system healthy')")
    assert len(policyEngine.policies) == numberOfPolicies + 1
    policyEngine.loadPolicy("test.system.nothealthy:not test.healthy -> test.system.log('system is not healthy')")
    assert len(policyEngine.policies) == numberOfPolicies + 2

    policyEngine.run()

def test_policyEngineLoading(temporaryDatabasePaths):

    policyEngine = PolicyEngine()
    numberOfPolicies = len(policyEngine.policies)

    policy = policyEngine.policyParser.parsePolicy("test.cpu.policy: (cpu.utilization >= 90.0) -> test.system.log('CPU utilization high'),test.system.log('CPU utilization high')")
    policyEngine.addPolicy(policy)

    policyEngine2 = PolicyEngine()
    assert "test.cpu.policy" in policyEngine2.policies
    assert len(policyEngine2.policies) == numberOfPolicies + 1

def test_policyHierarchy(temporaryDatabasePaths):
    """
    one
        one.one
            one.one.one
        one.two
        one.three
            one.three.one
            one.three.two
    two
        two.one

    """
    class Base(PolicyComponent):

        def __init__(self, name):
            super(Base, self).__init__(name,
                                       Healthy(),
                                       [ActionReference(Log(), [name])])

    one = Base("one")
    one_one = Base("one.one")
    one_one_one = Base("one.one.one")
    one_two = Base("one.two")
    one_three = Base("one.three")
    one_three_one = Base("one.three.one")
    one_three_two = Base("one.three.two")
    two = Base("two")
    two_one = Base("two.one")

    one.addPolicy(one_one)
    one_one.addPolicy(one_one_one)
    one.addPolicy(one_two)
    one.addPolicy(one_three)
    one_three.addPolicy(one_three_one)
    one_three.addPolicy(one_three_two)
    two.addPolicy(two_one)

    policyEngine = PolicyEngine()
    policyEngine.addPolicy(one)
    policyEngine.addPolicy(two)

#     policyInfos = policyEngine.policyDatabase.getPolicyInfos()
#     for policyInfo in policyInfos:
#         log.debug(policyInfo.toJSON(includeClassInfo=True, pretty=True))
#         log.debug(policyInfo.toJSON(pretty=True))
    assert policyEngine.policyDatabase.getPolicyInfo("one")
    assert policyEngine.policyDatabase.getPolicyInfo("one/one.one")
    assert policyEngine.policyDatabase.getPolicyInfo("one/one.one/one.one.one")
    assert policyEngine.policyDatabase.getPolicyInfo("one/one.two")
    assert policyEngine.policyDatabase.getPolicyInfo("one/one.three")
    assert policyEngine.policyDatabase.getPolicyInfo("one/one.three/one.three.one")
    assert policyEngine.policyDatabase.getPolicyInfo("one/one.three/one.three.two")
    assert policyEngine.policyDatabase.getPolicyInfo("two")
    assert policyEngine.policyDatabase.getPolicyInfo("two/two.one")

    policyEngine.run()
