import json
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

    def dump(self) -> dict:
        """Serialize the states of mutator into the single dictionary.
        Returns:
            the states of mutator.
        """
        return {"gadgets": [g.dump() for g in self.gadgets]}

    @classmethod
    def load(cls, dumps: str | dict) -> "APICombMutator":
        """Load from the state.
        Args:
            dumps: the dumped states from the method `APICombMutator.dump`.
        Returns:
            loaded api combination mutator.
        """
        if isinstance(dumps, str):
            with open(dumps):
                dumps = json.load(dumps)
        return cls([APIGadget.load(g) for g in dumps["gadgets"]])
