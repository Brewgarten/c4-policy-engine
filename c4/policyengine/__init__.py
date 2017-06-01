"""
A policy engine implementation with support for events and actions as well as textual representations
"""
from pkgutil import extend_path
__path__ = extend_path(__path__, __name__)

from .policyEngine import (Action, ActionReference,
                           BinaryOperator,
                           CachableEvent, Cache,
                           Event, EventReference,
                           Policy, PolicyComponent, PolicyDatabase, PolicyEngine, PolicyEngineProcess, PolicyInfo, PolicyParser, PolicyProperties, PolicyWrapper,
                           States,
                           UnaryOperator,
                           ValueEvent)

from ._version import get_versions
__version__ = get_versions()['version']
del get_versions
