from c4.policyengine import BinaryOperator

class Equal(BinaryOperator):

    id = "=="

    def evaluateOperation(self, one, two):
        if type(one) == type(two):
            return one is two
        return False

class GreaterThan(BinaryOperator):

    id = ">"

    def evaluateOperation(self, one, two):
        if type(one) == type(two):
            return one > two
        return False

class GreaterThanOrEqual(GreaterThan, Equal):

    id = ">="

    def evaluateOperation(self, one, two):
        if (GreaterThan.evaluateOperation(self, one, two) or
            Equal.evaluateOperation(self, one, two)):
            return True
        return False

class LessThan(BinaryOperator):

    id = "<"

    def evaluateOperation(self, one, two):
        if type(one) == type(two):
            return one < two
        return False

class LessThanOrEqual(LessThan, Equal):

    id = "<="

    def evaluateOperation(self, one, two):
        if (LessThan.evaluateOperation(self, one, two) or
            Equal.evaluateOperation(self, one, two)):
            return True
        return False
