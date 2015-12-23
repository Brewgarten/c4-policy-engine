import c4.policyengine.policyEngine

class And(c4.policyengine.policyEngine.BinaryOperator):

    id = "and"

    def evaluateOperation(self, one, two):
        if isinstance(one, bool) and isinstance(two, bool):
            return one and two
        return False

class Not(c4.policyengine.policyEngine.UnaryOperator):

    id = "not"

    def evaluateOperation(self, one):
        if isinstance(one, bool):
            return not one
        return False

class Or(c4.policyengine.policyEngine.BinaryOperator):

    id = "or"

    def evaluateOperation(self, one, two):
        if isinstance(one, bool) and isinstance(two, bool):
            return one or two
        return False
