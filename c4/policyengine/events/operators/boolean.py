"""
Boolean operators
"""
from c4.policyengine import BinaryOperator, UnaryOperator

class And(BinaryOperator):
    """
    `and` operator
    """
    id = "and"

    def evaluateOperation(self, one, two):
        if isinstance(one, bool) and isinstance(two, bool):
            return one and two
        return False

class Not(UnaryOperator):
    """
    `not` operator
    """
    id = "not"

    def evaluateOperation(self, one):
        if isinstance(one, bool):
            return not one
        return False

class Or(BinaryOperator):
    """
    `or` operator
    """
    id = "or"

    def evaluateOperation(self, one, two):
        if isinstance(one, bool) and isinstance(two, bool):
            return one or two
        return False
