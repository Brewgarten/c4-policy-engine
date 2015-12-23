from c4.policyengine import BinaryOperator, UnaryOperator

class And(BinaryOperator):

    id = "and"

    def evaluateOperation(self, one, two):
        if isinstance(one, bool) and isinstance(two, bool):
            return one and two
        return False

class Not(UnaryOperator):

    id = "not"

    def evaluateOperation(self, one):
        if isinstance(one, bool):
            return not one
        return False

class Or(BinaryOperator):

    id = "or"

    def evaluateOperation(self, one, two):
        if isinstance(one, bool) and isinstance(two, bool):
            return one or two
        return False
