import random

from agentfuzz.analyzer import APIGadget


class APICombMutator:
    """Mutator for API combination"""

    def __init__(self, gadgets: list[APIGadget]):
        self.gadgets = gadgets

    def select(self, comblen: int):
        # temporally return the random apis from the gadgets
        temp = [*self.gadgets]
        random.shuffle(temp)
        return temp[:comblen]
