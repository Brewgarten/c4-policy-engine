"""
Copyright (c) IBM 2015-2017. All Rights Reserved.
Project name: c4-policy-engine
This project is licensed under the MIT License, see LICENSE

A policy engine implementation with support for events and actions as well as textual representations
"""
from abc import ABCMeta, abstractmethod
from collections import OrderedDict
from datetime import datetime
import inspect
import logging
import multiprocessing
import re
import socket
import time
import traceback

from c4.messaging import RouterClient
import c4.policies
import c4.policyengine.actions
import c4.policyengine.events
import c4.policyengine.events.operators
from c4.system.backend import Backend
from c4.system.configuration import (States as ConfigStates, Roles)
from c4.system.messages import Operation
from c4.utils.enum import Enum
from c4.utils.jsonutil import JSONSerializable
from c4.utils.logutil import ClassLogger
from c4.utils.util import (callWithVariableArguments,
                           getFormattedArgumentString, getFullModuleName, getModuleClasses)


log = logging.getLogger(__name__)

class States(Enum):
    """
    Enumeration of states
    """
    ENABLED = "enabled"
    DISABLED = "disabled"

@ClassLogger
class Event(object):
    """
    An event implementation
    """
    __metaclass__ = ABCMeta
    id = None

    def __init__(self):
        pass
        # TODO: type, group, severity, description
        # see http://www-01.ibm.com/support/knowledgecenter/SSULQD_7.1.0/com.ibm.nz.adm.doc/r_sysadm_template_event_rules.html

    @abstractmethod
    def evaluate(self):
        """
        Evaluate the event

        .. note::

            Subclasses should implement this

        :returns: value
        """

    @property
    def value(self):
        """
        Value of the event
        """
        return self.evaluate()

    def __repr__(self, *args, **kwargs):
        return "({0})".format(self.id)

    def __str__(self, *args, **kwargs):
        return "({0} -> {1})".format(self.id, self.evaluate())

@ClassLogger
class EventReference(Event):
    """
    A reference to an :class:`Event`

    :param event: event
    :type event: :class:`Event`
    :param arguments: arguments
    :param keyValueArguments: key value arguments
    """
    def __init__(self, event, arguments=None, keyValueArguments=None):
        super(EventReference, self).__init__()
        self.event = event
        self.id = event.id
        if arguments is None:
            self.arguments = []
        else:
            self.arguments = arguments
        if keyValueArguments is None:
            self.keyValueArguments = {}
        else:
            self.keyValueArguments = keyValueArguments

    def evaluate(self):
        """
        Evaluate the specified event using the given
        arguments and key value arguments

        :returns: result
        """
        try:
            arguments = []
            for argument in self.arguments:
                if isinstance(argument, (EventReference, CachableEvent)):
                    arguments.append(argument.evaluate())
                elif isinstance(argument, Event):
                    raise ValueError("'{0}' needs to be an EventReference".format(repr(argument)))
                else:
                    arguments.append(argument)

            keyValueArguments = {}
            for key, value in self.keyValueArguments.items():
                if isinstance(value, (EventReference, CachableEvent)):
                    keyValueArguments[key] = value.evaluate()
                elif isinstance(value, Event):
                    raise ValueError("'{0}={1}' needs to be an EventReference".format(key, repr(value)))
                else:
                    keyValueArguments[key] = value

            return callWithVariableArguments(self.event.evaluate, *arguments, **keyValueArguments)
        except Exception as exception:
            self.log.error(self.event)
            self.log.exception(exception)

    def __repr__(self, *args, **kwargs):
        return "({0}{1})".format(self.id,
                                 getFormattedArgumentString(self.arguments, self.keyValueArguments))

    def __str__(self, evaluatedValue=None, *args, **kwargs):
        # TODO: what about if the value is actually None?
        if evaluatedValue is None:
            evaluatedValue = self.evaluate()

        return "({0}{1} -> {2})".format(self.id,
                                        getFormattedArgumentString(self.arguments, self.keyValueArguments),
                                        evaluatedValue)

@ClassLogger
class Action(object):
    """
    An action implementation
    """
    __metaclass__ = ABCMeta
    id = None

    @abstractmethod
    def perform(self):
        """
        Perform specified action

        .. note::

            Subclasses should add arguments as needed

        :returns: result
        """

    def __repr__(self, *args, **kwargs):
        return "{0}(...)".format(self.id)

@ClassLogger
class ActionReference(Action):
    """
    A reference to an :class:`Action`

    :param action: action
    :type action: :class:`Action`
    :param arguments: arguments
    :param keyValueArguments: key value arguments
    """
    def __init__(self, action, arguments=None, keyValueArguments=None):
        self.action = action
        self.id = action.id
        if arguments is None:
            self.arguments = []
        else:
            self.arguments = arguments
        if keyValueArguments is None:
            self.keyValueArguments = {}
        else:
            self.keyValueArguments = keyValueArguments

    def perform(self):
        """
        Perform specified action using the given
        arguments and key value arguments

        :returns: result
        """
        try:
            return callWithVariableArguments(self.action.perform, *self.arguments, **self.keyValueArguments)
        except Exception as exception:
            self.log.error(self.action)
            self.log.exception(exception)

    def __repr__(self, *args, **kwargs):
        return "{0}{1}".format(self.id, getFormattedArgumentString(self.arguments, self.keyValueArguments))

@ClassLogger
class BinaryOperator(Event):
    """
    A binary operator base class

    :param one: event one
    :type one: :class:`Event`
    :param two: event two
    :type two: :class:`Event`
    """
    __metaclass__ = ABCMeta
    id = "binaryOperator"

    def __init__(self, one, two):
        super(BinaryOperator, self).__init__()
        self.one = ValueEvent.create(one)
        self.two = ValueEvent.create(two)

    @abstractmethod
    def evaluateOperation(self, one, two):
        """
        Evaluate the binary operation with the specified operands
        """

    def evaluate(self):
        one = self.one.evaluate()
        two = self.two.evaluate()
        return self.evaluateOperation(one, two)

    def __repr__(self, *args, **kwargs):
        return "({0} {1} {2})".format(repr(self.one), self.id, repr(self.two))

    def __str__(self, *args, **kwargs):
        return "({0} {1} {2} -> {3})".format(self.one, self.id, self.two, self.evaluate())

@ClassLogger
class Cache(dict):
    """
    A memory-based dictionary cache
    """
    def __init__(self):
        super(Cache, self).__init__()
        self.enabled = True

@ClassLogger
class CachableEvent(Event):
    """
    An event which value can be cached

    :param cache: cache
    :type cache: :class:`Cache`
    :param event: event
    :type event: :class:`Event`
    """
    def __init__(self, cache, event):
        super(CachableEvent, self).__init__()
        self.cache = cache
        self.event = event
        self.id = event.id

    def evaluate(self):
        if self.cache.enabled:
            if self.id not in self.cache:
                self.cache[self.id] = self.event.evaluate()
            return self.cache[self.id]
        else:
            return self.event.evaluate()

    def __repr__(self, *args, **kwargs):
        return repr(self.event)

    def __str__(self, *args, **kwargs):
        if isinstance(self.event, EventReference):
            return self.event.__str__(evaluatedValue=self.evaluate())
        return "({0} -> {1})".format(self.id, self.evaluate())

@ClassLogger
class Policy(object):
    """
    A policy base class

    :param cache: cache
    :type cache: :class:`Cache`
    """
    __metaclass__ = ABCMeta
    id = None

    def __init__(self, cache=None):
        self.cache = cache
        self.state = States.ENABLED

    @property
    def description(self):
        """
        Formatted description based on the doc string
        """
        if not self.__doc__:
            return ""
        description = []
        for line in self.__doc__.splitlines():
            line = line.strip()
            if line and not line.startswith(":"):
                description.append(line)
        return "\n".join(description)

    @abstractmethod
    def evaluateEvent(self):
        """
        Evaluate the event to determine if the action for this policy should
        to be performed
        """

    @abstractmethod
    def performActions(self):
        """
        Perform actions specified for the policy if the event evaluated as
        ``True``
        """

    def __hash__(self, *args, **kwargs):
        return hash(repr(self))

    def __repr__(self, *args, **kwargs):
        return "{0}".format(self.id)

    def __str__(self, *args, **kwargs):
        return "{0}".format(self.id)

@ClassLogger
class PolicyComponent(Policy):
    """
    A policy component consisting of an event and respective list of actions

    :param name: name
    :type name: str
    :param event: event
    :type event: :class:`Event`
    :param actions: list of actions
    :param actions: [:class:`ActionReference`]
    """
    def __init__(self, name, event, actions, cache=None):
        super(PolicyComponent, self).__init__(cache)
        self.id = name
        self.event = event
        self.actions = actions
        self.policyHashes = {}
        self.policies = OrderedDict()

    def addPolicy(self, policy):
        """
        Add a child policy

        :param policy: policy
        :type policy: :class:`Policy`
        """
        policyHash = hash(policy)
        if policyHash in self.policyHashes:
            self.log.error("policy '%s' already exists", repr(policy))
        else:
            self.policyHashes[policyHash] = policy
            self.policies[policy.id] = policy
            if isinstance(policy, PolicyComponent):
                self.log.debug("'%s' added policy '%s' '%s'", self.id, policy.id, repr(policy))
            else:
                self.log.debug("'%s' added policy '%s'", self.id, policy.id)

    def evaluateEvent(self):
        return self.event.evaluate()

    def performActions(self):
        if self.actions:
            for action in self.actions:
                action.perform()

    def __hash__(self, *args, **kwargs):
        return hash(repr(self))

    def __repr__(self, *args, **kwargs):
        return "{0} -> {1}".format(repr(self.event), ",".join([str(action) for action in self.actions]))

    def __str__(self, *args, **kwargs):
        return "{0}: {1} -> {2}".format(self.id, self.event, ",".join([str(action) for action in self.actions]))

@ClassLogger
class PolicyDatabase(object):
    """
    An abstraction of the underlying database where policies are stored
    """
    def __init__(self):
        self.store = Backend().keyValueStore

    def addPolicyUsingName(self, fullPolicyName, policy):
        """
        Add a policy

        :param fullPolicyName: fully qualified policy name
        :type fullPolicyName: str
        :param policy: policy
        :type policy: :class:`Policy`
        """
        nameHierarchy = fullPolicyName.split("/")
        if len(nameHierarchy) == 1:
            # no parent
            if self.policyExists(policy.id):
                # with the ability to run policy engine on multiple nodes but with shared database this is acceptable
                self.log.debug("policy '%s' already exists", repr(policy))
                return False
            else:
                self.addPolicy(policy)

                # check if we can add children
                if hasattr(policy, "policies"):
                    for childPolicy in policy.policies.values():
                        self.addPolicyUsingName("{0}/{1}".format(fullPolicyName, childPolicy.id), childPolicy)

        else:
            self.log.warn("Parent child relationships not implemented yet")
            return False

        return True

    def addPolicy(self, policy):
        """
        Add a policy

        :param policy: policy
        :type policy: :class:`Policy`
        """
        policyInfo = self.getPolicyInfo(policy.id)
        if policyInfo:
            self.log.error("policy '%s' already exists", policyInfo.name)
            return None

        properties = {}
        if isinstance(policy, PolicyComponent):
            representation = repr(policy)
            policyType = "{}.{}".format(getFullModuleName(PolicyComponent), PolicyComponent.__name__)
        else:
            representation = policy.id
            policyType = "{}.{}".format(getFullModuleName(policy), policy.__class__.__name__)
            if policy.description:
                properties["description"] = policy.description

        policyKey = self.getKey(policy.id)
        propertiesKey = "{policyKey}/properties".format(policyKey=policyKey)
        representationKey = "{policyKey}/representation".format(policyKey=policyKey)
        stateKey = "{policyKey}/state".format(policyKey=policyKey)
        typeKey = "{policyKey}/type".format(policyKey=policyKey)

        transaction = self.store.transaction
        transaction.put(policyKey, policy.id)
        transaction.put(representationKey, representation)
        transaction.put(stateKey, policy.state.toJSON(includeClassInfo=True))
        transaction.put(typeKey, policyType)
        for key, value in properties.items():
            propertyKey = "{propertiesKey}/{key}".format(propertiesKey=propertiesKey, key=key)
            transaction.put(propertyKey, value)
        transaction.commit()

        if isinstance(policy, PolicyComponent):
            self.log.debug("stored policy '%s' '%s'", policy.id, representation)
        else:
            self.log.debug("stored policy '%s'", policy.id)

    def clear(self):
        """
        Remove all policies
        """
        self.store.deletePrefix("/policies/")

    def disablePolicy(self, fullPolicyName):
        """
        Disables the policy in the database given its name

        :param fullPolicyName: fully qualified policy name
        :type fullPolicyName: str
        """
        stateKey = self.getKey(fullPolicyName, "state")
        serializedState = self.store.get(stateKey)
        if not serializedState:
            self.log.error("could not disable '%s' because it does not exist", fullPolicyName)
            return
        self.store.put(stateKey, States.DISABLED.toJSON(includeClassInfo=True))

    def enablePolicy(self, fullPolicyName):
        """
        Enables the policy in the database given its name

        :param fullPolicyName: fully qualified policy name
        :type fullPolicyName: str
        """
        stateKey = self.getKey(fullPolicyName, "state")
        serializedState = self.store.get(stateKey)
        if not serializedState:
            self.log.error("could not enable '%s' because it does not exist", fullPolicyName)
            return
        self.store.put(stateKey, States.ENABLED.toJSON(includeClassInfo=True))

    def getKey(self, fullPolicyName, *additionalParts):
        """
        Get key for the specified policy

        :param fullPolicyName: fully qualified policy name
        :type fullPolicyName: str
        :returns: key
        :rtype: str
        """
        nameHierarchy = fullPolicyName.split("/")
        keyParts = [""]
        for name in nameHierarchy:
            keyParts.extend(["policies", name])
        keyParts.extend(additionalParts)
        return "/".join(keyParts)

    def getNestedPolicyInfos(self, parentKey, policyInfoMapping):
        """
        Get policies based on parent key and the already retrieved values

        :param parentKey: parent key
        :type parentKey: str
        :param policyInfoMapping: policy information mapping of key-value
        :type policyInfoMapping: dict
        """
        policies = {}
        policyKeyExpression = re.compile(r"(?P<policyKey>{parentKey}/policies/[^/]+)$".format(parentKey=parentKey))
        for key in policyInfoMapping.keys():
            match = policyKeyExpression.match(key)
            if match:
                policyKey = match.group("policyKey")
                propertiesKey = "{policyKey}/properties/".format(policyKey=policyKey)
                representationKey = "{policyKey}/representation".format(policyKey=policyKey)
                stateKey = "{policyKey}/state".format(policyKey=policyKey)
                typeKey = "{policyKey}/type".format(policyKey=policyKey)
                policyProperties = {
                    key.replace(propertiesKey, ""): value
                    for key, value in policyInfoMapping.items()
                    if key.startswith(propertiesKey)
                }

                policyInfo = PolicyInfo(
                    policyInfoMapping[policyKey],
                    policyInfoMapping[representationKey],
                    policyInfoMapping[stateKey],
                    policyInfoMapping[typeKey],
                    policyProperties
                )

                policyInfo.policies = self.getNestedPolicyInfos(policyKey, policyInfoMapping)
                policies[policyInfo.name] = policyInfo
        return policies

    def getNumberOfTopLevelPolicies(self):
        """
        Get number of top level policies

        :returns: number of top level policies
        :rtype: int
        """
        pattern = re.compile("/policies/[^/]+$")
        policies = {
            pattern.search(key)
            for key, _ in self.store.getPrefix("/policies/")
            if pattern.search(key)
        }
        return len(policies)

    def getPolicyInfo(self, fullPolicyName):
        """
        Get policy info for the specified policy

        :param fullPolicyName: fully qualified policy name
        :type fullPolicyName: str
        :returns: policy info
        :rtype: :class:`PolicyInfo`
        """
        policyKey = self.getKey(fullPolicyName)
        policyName = self.store.get(policyKey)
        if not policyName:
            return None

        policyPrefix = policyKey + "/"
        # map from key to value and deserialize value automatically
        policyInfoMapping = {
            key : JSONSerializable.fromJSON(value) if JSONSerializable.classAttribute in value else value
            for key, value in self.store.getPrefix(policyPrefix)
        }

        # deal with policy information
        propertiesKey = "{policyKey}/properties/".format(policyKey=policyKey)
        representationKey = "{policyKey}/representation".format(policyKey=policyKey)
        stateKey = "{policyKey}/state".format(policyKey=policyKey)
        typeKey = "{policyKey}/type".format(policyKey=policyKey)
        policyProperties = {
            key.replace(propertiesKey, ""): value
            for key, value in policyInfoMapping.items()
            if key.startswith(propertiesKey)
        }

        policyInfo = PolicyInfo(
            policyName,
            policyInfoMapping[representationKey],
            policyInfoMapping[stateKey],
            policyInfoMapping[typeKey],
            policyProperties
        )
        policyInfo.policies = self.getNestedPolicyInfos(policyKey, policyInfoMapping)

        return policyInfo

    def getPolicyInfos(self):
        """
        Get all policy infos

        :returns: list of policy infos
        :rtype: [:class:`PolicyInfo`]
        """
        policyInfoMapping = {
            key: JSONSerializable.fromJSON(value) if JSONSerializable.classAttribute in value else value
            for key, value in self.store.getPrefix("/policies")
        }
        return self.getNestedPolicyInfos("", policyInfoMapping).values()

    def getPolicyState(self, fullPolicyName):
        """
        Get the state of 'policy' if it exists

        :param fullPolicyName: fully qualified policy name
        :type fullPolicyName: str
        :returns: state of the policy if it exists else None
        :rtype: :class:`States`
        """
        stateKey = self.getKey(fullPolicyName, "state")
        value = self.store.get(stateKey)
        if value is None:
            self.log.error("could not get state because '%s' does not exist", fullPolicyName)
            return None
        return JSONSerializable.fromJSON(value)

    def policyExists(self, fullPolicyName):
        """
        Does the specified policy already exist

        :param fullPolicyName: fully qualified policy name
        :type fullPolicyName: str
        :returns: whether policy exists
        :rtype: bool
        """
        stateKey = self.getKey(fullPolicyName, "state")
        serializedState = self.store.get(stateKey)
        if serializedState:
            return True
        return False

@ClassLogger
class PolicyEngine(object):
    """
    Policy engine that allows iterating over policies and performing their actions
    based on whether the specified event matches

    :param properties: properties
    :type properties: dict
    """
    def __init__(self, properties=None):
        self.events = {}
        self.cache = Cache()
        self.cache.enabled = False
        self.actions = {}
        self.policyParser = PolicyParser(self)
        self.policies = OrderedDict()
        self.policyDatabase = PolicyDatabase()
        self.properties = properties or {}

        self.loadActions()
        self.loadEvents()
        orderedList = self.properties.get("policies", [] )
        includePoliciesFromDatabase = self.properties.get("include.policies.database", False)
        self.loadDefaultPolicies(orderedList=orderedList, includePoliciesFromDatabase=includePoliciesFromDatabase)

    def addAction(self, action):
        """
        Add known action

        :param action: action
        :type action: :class:`Action`
        """
        self.log.debug("adding action '%s'", action.id)
        self.actions[action.id] = action

    def addActions(self, actions):
        """
        Add known actions

        :param actions: actions
        :type actions: [:class:`Action`]
        """
        for action in actions:
            self.addAction(action)

    def addEvent(self, event):
        """
        Add known event

        :param event: event
        :type event: :class:`Event`
        """
        if event == Event:
            self.log.warn("cannot add base event class")
        elif issubclass(event, (UnaryOperator, BinaryOperator)):
            self.log.warn("cannot add operator '%s'", event.id)
        else:
            self.log.debug("adding event '%s'", event.id)
            self.events[event.id] = event

    def addEvents(self, events):
        """
        Add known events

        :param events: events
        :type events: [:class:`Event`]
        """
        for event in events:
            self.addEvent(event)

    def addPolicy(self, policy):
        """
        Add a policy

        :param policy: policy
        :type policy: :class:`Policy`
        """
        if self.policyDatabase.addPolicyUsingName(policy.id, policy):
            self.policies[policy.id] = policy
        elif policy.id not in self.policies:
            self.policies[policy.id] = policy

    def addPolicies(self, policies):
        """
        Add policies

        :param policies: policies
        :type policies: [:class:`Policy`]
        """
        for policy in policies:
            self.addPolicy(policy)

    def convertToPolicies(self, policyInfos):
        """
        Convert policy infos into actual policies

        :param policyInfos: policy infos
        :type policyInfos: [:class:`PolicyInfo`]
        :returns: policies
        :rtype: [:class:`Policy`]
        """
        policyComponentType = "{}.{}".format(getFullModuleName(PolicyComponent), PolicyComponent.__name__)

        policies = []
        for policyInfo in policyInfos:

            if policyInfo.type == policyComponentType:

                try:
                    policy = self.policyParser.parsePolicy(policyInfo.name + ":" + policyInfo.representation)
                    policy.state = policyInfo.state

                    # load children
                    if policyInfo.policies:
                        childPolicies = self.convertToPolicies(policyInfo.policies.values())
                        for childPolicy in childPolicies:
                            policy.addPolicy(childPolicy)

                    policies.append(policy)
                    self.log.debug("loaded policy '%s: %s'", policy.id, repr(policy))

                except Exception as exception:
                    self.log.error("could not load policy '%s': '%s': %s", policyInfo.name, policyInfo.representation, exception)

            else:
                try:
                    # get class info
                    info = policyInfo.type.split(".")
                    className = str(info.pop())
                    moduleName = ".".join(info)

                    # load class from module
                    module = __import__(moduleName, fromlist=[className])
                    clazz = getattr(module, className)

                    # create instance based off constructor
                    args = inspect.getargspec(clazz.__init__)
                    if len(args[0]) > 1:
                        policy = clazz(self.cache)
                    else:
                        policy = clazz()
                    policy.state = policyInfo.state
                    policies.append(policy)
                    self.log.debug("loaded policy '%s' of type '%s'", policyInfo.name, policyInfo.type)
                except Exception as exception:
                    self.log.error("could not load policy '%s' of type '%s': %s", policyInfo.name, policyInfo.type, exception)

        return policies

    def disablePolicy(self, policy):
        """
        Disables the given policy
        """
        self.log.debug("Disabling policy %s", str(policy))
        policyInfo = self.policyDatabase.getPolicyInfo(policy.id)
        if policyInfo is None:
            self.log.error("Unable to get policy from the database: %s", str(policy))
            return
        # disable the policy in memory and in the database
        if policy.state == States.ENABLED:
            policy.state = States.DISABLED
            self.policyDatabase.disablePolicy(policy.id)
        else:
            self.log.info("Policy is already disabled %s", str(policy))

    def enablePolicy(self, policy):
        """
        Enables the given policy
        """
        self.log.debug("Enabling policy %s", str(policy))
        policyInfo = self.policyDatabase.getPolicyInfo(policy.id)
        if policyInfo is None:
            self.log.error("Unable to get policy from the database: %s", str(policy))
            return
        # enable the policy in memory and in the database
        if not policy.isEnabled():
            policy.state = States.ENABLED
            self.policyDatabase.enablePolicy(policy.id)
        else:
            self.log.info("Policy is already enabled %s", str(policy))

    def loadActions(self):
        """
        Loads Actions from the c4/system/policies directory.
        """
        actions = getModuleClasses(c4.policyengine.actions, Action)
        actions.extend(getModuleClasses(c4.policies, Action))
        # filter out base classes
        actions = [action for action in actions if action != Action and action != ActionReference]
        self.addActions(actions)

    def loadDefaultPolicies(self, orderedList=None, includePoliciesFromDatabase=False):
        """
        Loads Policies from the c4/system/policies directory.

        :param orderedList: List of policy ids to include
        :type orderedList: list
        :param includePoliciesFromDatabase: Include policies form database?
        :type includePoliciesFromDatabase: boolean
        """
        # short circuit for empty list
        if not orderedList:
            self.log.info("Configuration did not specify any policies to load" )
            return

        # load policies
        policies = getModuleClasses(c4.policies, Policy)
        # filter out base class
        policies = [policy for policy in policies if policy != Policy]

        # build temporary unordered dict
        policyDict = {}
        for policy in policies:
            policyDict[policy.id] = policy

        wrappedPolicyDict = {}
        wrappedPolicies = getModuleClasses(c4.policies, PolicyWrapper)
        # remove base class
        if PolicyWrapper in wrappedPolicies:
            wrappedPolicies.remove(PolicyWrapper)
        for wrappedPolicy in wrappedPolicies:
            policyString = wrappedPolicy.id + ":" + wrappedPolicy.policy
            try:
                policy = self.policyParser.parsePolicy(policyString)
                wrappedPolicyDict[policy.id] = policy
            except Exception as exception:
                self.log.exception("could not parse policy wrapper '%s': %s", policyString, exception)

        dbPolicyDict = {}
        if includePoliciesFromDatabase:
            dbPolicies = self.getPoliciesFromDatabase()
            for policy in dbPolicies:
                dbPolicyDict[policy.id] = policy

        self.policies.clear()
        # We are specifying an order for loading the policies, but we have 3 sources the policies could be loaded from,
        # and the different sources have slightly different behaviors so go through the list to see if the policy can
        # be found and then load it based on the source; ie class properties will be type 1, policy wrapper will be type 2,
        # and policies that were custom added will be loaded from the database as type 3

        # Note that because we are not loading all policies anymore, it isn't sufficient to just check to see if the policy
        # database has policies loaded; also because we support dynamic loading it isn't sufficient to always load defaults
        for policyId in orderedList:
            try:
                policy = policyDict.get(policyId, None)
                policyType = 1
                if not policy:
                    policy = wrappedPolicyDict.get(policyId, None)
                    policyType = 2
                    if not policy:
                        policy = dbPolicyDict.get(policyId, None)
                        policyType = 3

                if policy:
                    if policyType == 1:
                        self.log.debug("loading default policy '%s' of type '%s.%s'", policy.id, policy.__module__, policy.__name__)
                        self.addPolicy(policy(self.cache))
                    elif policyType == 2:
                        self.log.debug("loading default policy '%s' from wrapper", policy.id)
                        self.addPolicy(policy)
                    else:
                        self.log.debug("loading default policy '%s' from database", policy.id)
                        self.addPolicy(policy)
                else:
                    self.log.error("Configuration error - policy: '%s' not found", policyId )
            except Exception as exception:
                self.log.exception(exception)

    def loadEvents(self):
        """
        Loads Events from the c4/system/policies directory.
        """
        events = getModuleClasses(c4.policyengine.events, Event)
        events.extend(getModuleClasses(c4.policies, Event))
        # filter out base classes and operators
        events = [event for event in events if event != Event and not issubclass(event, (UnaryOperator, BinaryOperator))]
        self.addEvents(events)

    def getPoliciesFromDatabase(self):
        """
        Get policies from the policy database table

        :returns: policies
        :rtype: [:class:`Policy`]
        """
        return self.convertToPolicies(self.policyDatabase.getPolicyInfos())

    def loadPolicy(self, string):
        """
        Load a policy into the engine

        :param string: policy string
        :type string: str
        """
        try:
            policy = self.policyParser.parsePolicy(string)
            self.addPolicy(policy)
        except Exception as exception:
            self.log.error("could not load policy '%s': %s", string, exception)

    def run(self, policy=None):
        """
        If a policy is given then check if specified event
        matches and perform actions accordingly, followed
        by running its child policies.

        If no policy is specified start with root policies.

        :param policy: policy
        :type policy: :class:`Policy`
        """
        if policy:
            start = datetime.utcnow()
            if policy.evaluateEvent():
                self.log.debug("event match for '%s'", policy)
                policy.performActions()
                if hasattr(policy, "policies"):
                    for childPolicy in policy.policies.values():
                        if childPolicy.state == States.ENABLED:
                            try:
                                self.run(childPolicy)
                            except Exception as exception:
                                self.log.exception(exception)
            else:
                self.log.debug("no event match for '%s'", policy)
            end = datetime.utcnow()
            self.log.debug("executing policy '%s' took %s", policy.id, end-start)
            self.checkPerformanceIssues(policy.id, start, end)

        else:
            start = datetime.utcnow()

            # clear cache on events
            self.cache.clear()
            self.cache.enabled = True

            # go through policies in order
            for policy in self.policies.values():
                if policy.state == States.ENABLED:
                    try:
                        self.run(policy)
                    except Exception as exception:
                        self.log.exception(exception)
                else:
                    self.log.debug("'%s' disabled", policy.id)

            # clear cache on events
            self.cache.clear()
            self.cache.enabled = False

            end = datetime.utcnow()
            self.log.debug("executing policy engine took %s", end-start)

    def updateFromDatabase(self):
        """
        Update all policies from database (includes list and state).
        """
        start = datetime.utcnow()
        # check policy list to see if it needs updating
        node = self.properties.get('node', None)
        name = self.properties.get('name', None)
        expectedPolicies = None
        role = None
        if node and name:
            configuration = Backend().configuration
            role = configuration.getRole(node)
            if role != Roles.DISABLED:
                roleInfo = configuration.getRoleInfo(role=role)
                if roleInfo:
                    deviceInfo = roleInfo.devices.get(name, None)
                    if deviceInfo:
                        properties = deviceInfo.properties
                        if properties:
                            expectedPolicies = properties.get('policies', [])
            else:
                self.log.info("Node is disabled removing policies...")
                expectedPolicies = []
                self.policies.clear()

        if expectedPolicies or (role and role == Roles.DISABLED):
            replacePolicies = False
            # check for extra policies
            for policy in self.policies.keys():
                if policy not in expectedPolicies:
                    replacePolicies = True
                    break
            if not replacePolicies:
                # check for missing policies
                for policy in expectedPolicies:
                    if policy not in self.policies.keys():
                        replacePolicies = True
                        break
            # if mismatch then replace all policies (since order matters)
            if replacePolicies:
                self.log.info("Expected policies: %s", str(expectedPolicies))
                self.log.info("Actual policies: %s", str(self.policies.keys()))
                self.log.info("Correcting policies...")
                includePoliciesFromDatabase = self.properties.get("include.policies.database", False)
                self.loadDefaultPolicies(orderedList=expectedPolicies, includePoliciesFromDatabase=includePoliciesFromDatabase)
                #TODO send device name a setPolicies operation message to update it's status for reporting
                address = socket.gethostname().split(".")[0]
                client = RouterClient(address)
                client.forwardMessage(Operation("{0}/{1}".format(node, name),
                                                "setPolicies",
                                                policies=expectedPolicies))
        # go through policies in order to update states
        for key, policy in self.policies.items():
            dbState = self.policyDatabase.getPolicyState(policy.id)
            if policy.state != dbState:
                policy.state = dbState
                self.policies[key] = policy

        end = datetime.utcnow()
        self.log.debug("updating policy engine took %s", end-start)

    def checkPerformanceIssues(self, policyName, start, end):
        """
        TODO: documentation
        """
        # this value might require tweaking for complex policies and multinode systems
        policyPerfomanceWarn = self.properties.get("performance.warning.threshold", 2)
        execTime = (end-start).total_seconds()
        if execTime > policyPerfomanceWarn:
            self.log.warning("Executing policy '%s' has taken: %s seconds", policyName, execTime)

class PolicyInfo(JSONSerializable):
    """
    Policy information

    :param name: name
    :type name: str
    :param representation: representation
    :type representation: str
    :param state: state
    :type state: :class:`States`
    :param policyType: type
    :type policyType: str
    :param properties: properties
    :type properties: dict
    """
    def __init__(self, name, representation, state, policyType, properties):
        self.name = name
        self.representation = representation
        self.state = state
        self.type = policyType
        self.policies = None
        self.properties = properties

    def addPolicyInfo(self, policyInfo):
        """
        Add child policy information

        :param policyInfo: policy info
        :type policyInfo: :class:`PolicyInfo`
        :returns: :class:`PolicyInfo`
        """
        if self.policies is None:
            self.policies = OrderedDict()
        if policyInfo.name in self.policies:
            log.error("'%s' already part of '%s'", policyInfo.name, self.name)
        else:
            self.policies[policyInfo.name] = policyInfo
        return self

@ClassLogger
class PolicyParser(object):
    """
    Base implementation of a policy parser using ``pyparsing``

    :param policyEngine: policy engine
    :type policyEngine: :class:`PolicyEngine`
    """
    def __init__(self, policyEngine):
        self.policyEngine = policyEngine
        self.unaryOperators = {}
        self.binaryOperators = {}

        import pyparsing

        # constant values
        self.stringConstantElement = (pyparsing.QuotedString("\"", unquoteResults=True) |
                                      pyparsing.QuotedString("'", unquoteResults=True))
        self.numberConstantElement = pyparsing.Word(pyparsing.nums + ".")
        def numberConstantElementParseAction(tokens):
            """
            Parse number constants into `float` or `int`
            """
            self.log.debug("found number constant '%s'", tokens[0])
            if "." in tokens[0]:
                try:
                    return float(tokens[0])
                except:
                    pass
            else:
                try:
                    return int(tokens[0])
                except:
                    pass
            return tokens
        self.numberConstantElement.addParseAction(numberConstantElementParseAction)

        self.constantElement = self.stringConstantElement |  self.numberConstantElement

        # key-value pair constant
        self.namedConstantElement = pyparsing.Word(pyparsing.alphanums) + "=" + self.constantElement
        def namedConstantParseAction(string, location, tokens):
            """
            Parse named constant into a key-value dictionary
            """
            self.log.debug("found named constant  '%s = %s'", tokens[0], tokens[2])
            return {tokens[0]: tokens[2]}
        self.namedConstantElement.addParseAction(namedConstantParseAction)

        self.eventReferenceElement = pyparsing.Forward()

        # parameters
        self.parameterElement = self.constantElement | self.namedConstantElement | self.eventReferenceElement
        self.parametersElement = self.parameterElement + pyparsing.ZeroOrMore(pyparsing.Suppress(",") + self.parameterElement)
        def parametersParseAction(string, location, tokens):
            """
            Parse parameters into arguments and key value arguments tuple
            """
            arguments = []
            keyValueArguments = {}
            for parameter in tokens:
                self.log.debug("found parameter '%s'", repr(parameter))
                if isinstance(parameter, dict):
                    keyValueArguments.update(parameter)
                else:
                    arguments.append(parameter)
            return (arguments, keyValueArguments)
        self.parametersElement.addParseAction(parametersParseAction)

        # event references
        self.eventReferenceElement << (
            (
                pyparsing.Word(pyparsing.alphanums + ".") +
                pyparsing.Suppress("(") +
                pyparsing.Optional(self.parametersElement) +
                pyparsing.Suppress(")")) |
            pyparsing.Word(pyparsing.alphanums + ".")
        )
        def eventReferenceElementParseAction(string, location, tokens):
            """
            Parse event references into a cachable event
            """
            if len(tokens) == 1:
                self.log.debug("found event reference '%s'", tokens[0])
                parameters = ([], {})
            else:
                self.log.debug("found event reference '%s%s'", tokens[0], repr(tokens[1]))
                parameters = tokens[1]

            if tokens[0] not in self.policyEngine.events:
                raise pyparsing.ParseFatalException(
                    string, location,
                    "found unknown event reference '{0}'".format(repr(tokens[0])))

            # set up event implementation
            event = self.policyEngine.events[tokens[0]]()
            self.checkParameters(event, "evaluate", parameters[0], parameters[1])

            return CachableEvent(
                self.policyEngine.cache,
                EventReference(event, parameters[0], parameters[1]))
        self.eventReferenceElement.addParseAction(eventReferenceElementParseAction)

        # event operators
        self.unaryOperatorElement = pyparsing.Or([])
        self.binaryOperatorElement = pyparsing.Or([])

        # TODO: outsource to load function?
        unaryOperatorList = getModuleClasses(c4.policyengine.events.operators, UnaryOperator)
        for operatorImplementation in unaryOperatorList:
            self.unaryOperators[operatorImplementation.id] = operatorImplementation
            self.unaryOperatorElement.append(pyparsing.Or(operatorImplementation.id))

        binaryOperatorList = getModuleClasses(c4.policyengine.events.operators, BinaryOperator)
        for operatorImplementation in binaryOperatorList:
            self.binaryOperators[operatorImplementation.id] = operatorImplementation
            self.binaryOperatorElement.append(pyparsing.Or(operatorImplementation.id))

        # basic value event with an optional unary operator
        self.valueEventElement = (
            pyparsing.Optional(self.unaryOperatorElement) +
            (self.constantElement | self.eventReferenceElement)
        )
        def valueEventElementParseAction(string, location, tokens):
            """
            Parse value event
            """
            if len(tokens) == 1:
                self.log.debug("found event '%s'", repr(tokens[0]))
                return tokens[0]

            # check for unary operators
            if len(tokens) == 2:
                self.log.debug("found event '%s %s'", tokens[0], repr(tokens[1]))
                if tokens[0] in self.unaryOperators:
                    return self.unaryOperators[tokens[0]](tokens[1])
                else:
                    raise pyparsing.ParseException("found unknown unary operator '{0}'".format(repr(tokens[0])))
        self.valueEventElement.addParseAction(valueEventElementParseAction)

        # complex event that may consist of a combination of events
        self.eventElement = pyparsing.Forward()
        self.eventElement << (
            (
                pyparsing.Optional(self.unaryOperatorElement) + pyparsing.Suppress("(") + self.eventElement + pyparsing.Suppress(")") +
                pyparsing.Optional(
                    self.binaryOperatorElement +
                    pyparsing.Or([
                        pyparsing.Optional(self.unaryOperatorElement) + pyparsing.Suppress("(") + self.eventElement + pyparsing.Suppress(")"),
                        self.valueEventElement])
                )
            ) |
            (self.valueEventElement + self.binaryOperatorElement + self.valueEventElement) |
            self.valueEventElement
        )
        def eventElementParseAction(string, location, tokens):
            """
            Parse event
            """
            if len(tokens) == 1:
                self.log.debug("found event '%s'", repr(tokens[0]))
                return tokens[0]

            # check for unary operators
            if len(tokens) == 2:
                self.log.debug("found event '%s %s'", tokens[0], repr(tokens[1]))
                if tokens[0] in self.unaryOperators:
                    return self.unaryOperators[tokens[0]](tokens[1])
                else:
                    raise pyparsing.ParseException("found unknown unary operator '{0}'".format(repr(tokens[0])))

            # check for binary operators
            if len(tokens) == 3:
                self.log.debug("found event '%s %s %s)'", repr(tokens[0]), tokens[1], repr(tokens[2]))
                if tokens[1] in self.binaryOperators:
                    return self.binaryOperators[tokens[1]](tokens[0], tokens[2])
                else:
                    raise pyparsing.ParseException("found unknown binary operator '{0}'".format(tokens[1]))
        self.eventElement.addParseAction(eventElementParseAction)

        # action identifier
        self.actionIdElement = pyparsing.Word(pyparsing.alphanums + ".")

        # action specified by an id and optional parameters
        self.actionElement = (self.actionIdElement +
                              pyparsing.Suppress("(") + pyparsing.Optional(self.parametersElement) + pyparsing.Suppress(")"))
        def actionElementParseAction(string, location, tokens):
            """
            Parse action into an action reference
            """
            if len(tokens) == 1:
                self.log.debug("found action '%s'", tokens[0])
                parameters = ([], {})
            else:
                self.log.debug("found action '%s%s'", tokens[0], repr(tokens[1]))
                parameters = tokens[1]

            if tokens[0] not in self.policyEngine.actions:
                raise pyparsing.ParseFatalException(
                    string, location,
                    "found unknown action reference '{0}'".format(tokens[0]))

            # set up action implementation
            action = self.policyEngine.actions[tokens[0]]()
            arguments = parameters[0]
            keyValueArguments = parameters[1]
            handlerArgSpec = inspect.getargspec(action.perform)
            handlerArguments = handlerArgSpec[0][1:]

            # check for named arguments
            handlerKeyValueArguments = {}
            if handlerArgSpec[3]:
                keys = handlerArguments[-len(handlerArgSpec[3]):]
                handlerKeyValueArguments = dict(zip(keys, handlerArgSpec[3]))
                handlerArguments = handlerArguments[:len(handlerArguments)-len(handlerArgSpec[3])]

            # make sure we have at least the number of arguments that the action requires
            if len(handlerArguments) != len(arguments):
                raise pyparsing.ParseFatalException(
                    string, location,
                    "action '{0}' requires {1} arguments but {2}: {3} are given".format(
                        action, len(handlerArguments), len(arguments), arguments))

            # check for unknown named arguments
            for key in keyValueArguments:
                if key not in handlerKeyValueArguments:
                    raise pyparsing.ParseFatalException(
                        string, location,
                        "action '{0}' does not have a named argument '{1}'".format(action, key))

            return ActionReference(self.policyEngine.actions[tokens[0]](), parameters[0], parameters[1])
        self.actionElement.addParseAction(actionElementParseAction)

        # list of actions
        self.actionsElement = self.actionElement + pyparsing.ZeroOrMore(pyparsing.Suppress(",") + self.actionElement)

        # policy element consisting of a name, an event and a set of actions
        self.policyElement = pyparsing.Word(pyparsing.alphanums + "." + "_") + pyparsing.Suppress(":") + self.eventElement + pyparsing.Suppress("->") + self.actionsElement

    def checkParameters(self, o, method, arguments, keyValueArguments):
        """
        Check parameters for the specified method

        :param o: object
        :type o: object
        :param method: method
        :type method: str
        :param arguments: arguments
        :type arguments: list
        :param keyValueArguments: key value arguments
        :type keyValueArguments: dict
        :raises ValueError: if parameters are not valid
        """

        # set up implementation
        handlerArgSpec = inspect.getargspec(getattr(o, method))
        handlerArguments = handlerArgSpec[0][1:]

        # check for named arguments
        handlerKeyValueArguments = {}
        if handlerArgSpec[3]:
            keys = handlerArguments[-len(handlerArgSpec[3]):]
            handlerKeyValueArguments = dict(zip(keys, handlerArgSpec[3]))
            handlerArguments = handlerArguments[:len(handlerArguments)-len(handlerArgSpec[3])]

        # make sure we have at least the number of arguments that the object requires
        if len(handlerArguments) != len(arguments) and handlerArgSpec[1] is None:
            raise ValueError("object '{0}' requires {1} arguments but {2}: {3} are given".format(
                repr(o), len(handlerArguments), len(arguments), arguments))

        # check for unknown named arguments
        for key in keyValueArguments:
            if key not in handlerKeyValueArguments:
                raise ValueError("object '{0}' does not have a named argument '{1}'".format(repr(o), key))

    def parseAction(self, string):
        """
        Parse string into :class:`Action`

        :returns: :class:`Action`
        """
        return self.actionElement.parseString(string, parseAll=True)[0]

    def parseActions(self, string):
        """
        Parse string into multiple :class:`Action` s

        :returns: [:class:`Action`]
        """
        return self.actionsElement.parseString(string, parseAll=True)

    def parseEvent(self, string):
        """
        Parse string into :class:`Event`

        :returns: :class:`Event`
        """
        return self.eventElement.parseString(string, parseAll=True)[0]

    def parsePolicy(self, string):
        """
        Parse string into :class:`Policy`

        :returns: :class:`Policy`
        """
        policyItems = self.policyElement.parseString(string, parseAll=True)
        return PolicyComponent(policyItems[0], policyItems[1], policyItems[2:])

@ClassLogger
class PolicyEngineProcess(multiprocessing.Process):
    """
    Policy engine process

    :param properties: properties
    :type properties: dict
    """
    def __init__(self, properties=None):
        super(PolicyEngineProcess, self).__init__(name="Policy engine")
        self.properties = properties or {}
        self.initial = self.properties.get("policy.timer.initial", 5)
        self.repeat = self.properties.get("policy.timer.repeat", -1)
        self.interval = self.properties.get("policy.timer.interval", 10)
        self.updateEnabled = self.properties.get("update.from.db", False)

    def run(self):
        """
        The implementation of the policy engine process
        """
        policyEngine = PolicyEngine(properties=self.properties)
        policies = policyEngine.policies
        self.log.info("policies: %s", str(policies))
        try:
            # wait until device managers transition to running before starting
            node = self.properties.get('node', None)
            devicesNotRunning = self.getDevicesNotRunning(node)
            while len(devicesNotRunning) > 0:
                self.log.info("Waiting for devices to become running: %s", ", ".join(devicesNotRunning))
                time.sleep(self.interval)
                devicesNotRunning = self.getDevicesNotRunning(node)

            time.sleep(self.initial)
            if self.repeat < 0:
                while True:
                    if self.updateEnabled:
                        policyEngine.updateFromDatabase()
                    policyEngine.run()
                    time.sleep(self.interval)
            else:
                while self.repeat >= 0:
                    policyEngine.run()
                    time.sleep(self.interval)
                    self.repeat -= 1
        except KeyboardInterrupt:
            self.log.debug("Exiting %s", self.name)
        except:
            self.log.debug("Forced exiting %s", self.name)
            self.log.error(traceback.format_exc())

    def getDevicesNotRunning(self, node):
        """
        Build a list of devices on this node that are not in running state.
        :param node: node to get devices for
        :type node: str
        :returns: list of device names
        """
        devices = Backend().configuration.getDevices(node, flatDeviceHierarchy=True)
        devicesNotRunning = []
        for deviceInfo in devices.values():
            if deviceInfo.state != ConfigStates.RUNNING:
                devicesNotRunning.append(deviceInfo.name)
        return devicesNotRunning

class PolicyProperties(JSONSerializable):
    """
    Policy properties
    """
    def __init__(self):
        self.description = None

@ClassLogger
class PolicyWrapper(object):
    """
    Derived classes need to provide an id and policy string.
    The PolicyWrapper class is used to load policies from disk,
    see c4/system/policies/
    """
    id = ""
    policy = ""

@ClassLogger
class UnaryOperator(Event):
    """
    A unary operator base class

    :param one: event one
    :type one: :class:`Event`
    """
    __metaclass__ = ABCMeta
    id = "unaryOperator"

    def __init__(self, one):
        super(UnaryOperator, self).__init__()
        self.one = ValueEvent.create(one)

    @abstractmethod
    def evaluateOperation(self, one):
        """
        Evaluate the unary operation with the specified operands
        """

    def evaluate(self):
        one = self.one.evaluate()
        return self.evaluateOperation(one)

    def __repr__(self, *args, **kwargs):
        return "({0} {1})".format(self.id, repr(self.one))

    def __str__(self, *args, **kwargs):
        return "({0} {1} -> {2})".format(self.id, self.one, self.evaluate())

@ClassLogger
class ValueEvent(Event):
    """
    A base value event

    :param value: value
    """
    id = "value"

    def __init__(self, value):
        super(ValueEvent, self).__init__()
        self._value = value

    def evaluate(self):
        """
        Return the value of the event

        :returns: value
        """
        return self._value

    @staticmethod
    def create(value):
        """
        Create a :class:`ValueEvent` given the value.

        .. note::

            If ``value`` is already an :class:`Event` then
            itself is returned instead

        :param value: value
        """
        if isinstance(value, Event):
            return value
        else:
            return ValueEvent(value)

    def __repr__(self, *args, **kwargs):
        return repr(self._value)

    def __str__(self, *args, **kwargs):
        return str(self.evaluate())
