import random

from agentfuzz.analyzer import APIGadget, Coverage


class APICombMutator:
    """Mutator for API combination"""

    def __init__(self, gadgets: list[APIGadget]):
        self.gadgets = gadgets

    def converge(self) -> bool:
        # TODO: check api mutation convergence
        return True

    def select(self, minlen: int, maxlen: int):
        # temporally return the random apis from the gadgets
        temp = [*self.gadgets]
        random.shuffle(temp)
        return temp[:minlen]

    def feedback(self, cov: Coverage):
        # TODO: feedback the api mutator with coverage
        pass
