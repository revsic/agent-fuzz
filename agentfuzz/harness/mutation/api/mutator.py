import json
import random

from agentfuzz.analyzer import APIGadget, Coverage


class APICombMutator:
    """Mutator for API combination"""

    def __init__(
        self,
        gadgets: list[APIGadget],
        counter: dict[str, dict[str, int]] | None = None,
        seeds: dict[str, dict] | None = None,
        exponent: float = 1.0,
    ):
        """Initialize the mutator.
        Args:
            gadgets: a list of the api gadgets.
            counter: a counter for the number of seeds and prompts containing the gadget.
        """
        self.gadgets = gadgets
        if counter is None:
            counter = {g.signature(): {"prompt": 0, "seed": 0} for g in gadgets}
        self.counter = counter
        self.seeds = seeds or {}
        self.exponent = exponent

    def append_seeds(self, path: str):
        # TODO: Extract the critical call and ompute the quality
        pass

    def select(self, coverage: Coverage, minlen: int, maxlen: int) -> list[APIGadget]:
        """Select the APIs w.r.t. the energies and qualities.
        Args:
            coverage: a list of API coverages.
            minlen, maxlen: the minimum/maximum length of a api list.
        Returns:
            a list of selected apis.
        """
        energies = self.energy(coverage)
        # from PromptFuzz
        det = min(len(self.seeds) / 100, 0.8) > random.random()
        if len(self.seeds) > 0 and det:
            return self._mutate_from_seeds(energies, minlen, maxlen)
        # load the highest energies
        return self._highest_energies(energies, maxlen)

    def _highest_energies(self, energies: list[float], len_: int) -> list[APIGadget]:
        """Return the gadgets of top-k highest energies.
        If there are gadgets of the same energy, sampled above those.

        Args:
            energies: a list of energies, that order of `self.gadgets`.
            len_: the length of the returning list.
        Returns:
            a list of sampled gadgets
        """
        # group w.r.t. the energy
        grouped = {}
        for gadget, energy in zip(self.gadgets, energies):
            if energy not in grouped:
                grouped[energy] = []
            grouped[energy].append(gadget)
        # order with descending order
        grouped = sorted(grouped.items(), key=lambda x: x[0], reverse=True)
        sampled = []
        for energy, gadgets in grouped:
            # if remaining length cover all gadgets of the current bin
            if len(gadgets) <= len_:
                sampled.extend(gadgets)
                len_ -= len(gadgets)
                continue
            # only a proper subset of the gadgets can be included
            random.shuffle(gadgets)
            sampled.extend(gadgets[:len_])
            break
        return sampled

    def _mutate_from_seeds(
        self, energies: list[float], minlen: int, maxlen: int
    ) -> list[APIGadget]:
        """Sample and mutate the API combination from the harness banks.
        Args:

        """
        (seed,) = random.choices(
            self.seeds,
            [q["quality"] for q in self.seeds.values()],
            k=1,
        )
        names = set(self.seeds[seed]["critical_path"])
        gadgets = [g for g in self.gadgets if g.name in names]
        # TODO: mutator

    def converge(self) -> bool:
        # TODO: check api mutation convergence
        return False

    def _energy(self, cov: float, seed: int, prompt: int) -> float:
        """Compute the energy of a single API.
        Args:
            cov: a branch coverage of the given API.
            seed: the number of the seeds containing the API.
            prompt: the number of the prompts containing the API.
        Returns:
            a energy value.
        """
        return (1 - cov) / ((1 + seed) * (1 + prompt)) ** self.exponent

    def energy(self, coverage: Coverage) -> list[float]:
        """Compute the energy for scheduling the api mutation.
        Args:
            coverage: a list of API coverages.
        Returns:
            list of energies that order of `self.gadgets`.
        """
        return [
            self._energy(coverage.cover(g.name), cnt["seed"], cnt["prompt"])
            for g in self.gadgets
            if (cnt := self.counter[g.signature()])
        ]

    def dump(self) -> dict:
        """Serialize the states of mutator into the single dictionary.
        Returns:
            the states of mutator.
        """
        return {
            "gadgets": [g.dump() for g in self.gadgets],
            "counter": self.counter,
            "seeds": self.seeds,
        }

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
        return cls(
            [APIGadget.load(g) for g in dumps["gadgets"]],
            counter=dumps["counter"],
            seeds=dumps["seeds"],
        )
