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

    def _group_energies(
        self, energies: list[float] | list[tuple[APIGadget, float]]
    ) -> list[tuple[float, list[APIGadget]]]:
        """Group the gadgets w.r.t. the energies.
        Args:
            energies: a list of the energies, that order of `self.gadgets` if the given is list[float].
        Returns:
            grouped gadget, energy-descending order.
        """
        if len(energies) == 0:
            return []
        fst, *_ = energies
        if isinstance(fst, float):
            energies = zip(self.gadgets, energies)
        # group w.r.t. the energy
        grouped = {}
        for gadget, energy in energies:
            if energy not in grouped:
                grouped[energy] = []
            grouped[energy].append(gadget)
        # order with descending order
        return sorted(grouped.items(), key=lambda x: x[0], reverse=True)

    def _highest_energies(
        self, energies: list[float] | list[tuple[APIGadget, float]], len_: int
    ) -> list[APIGadget]:
        """Return the gadgets of top-k highest energies.
        If there are gadgets of the same energy, sampled above those.

        Args:
            energies: a list of energies, that order of `self.gadgets` if the given is list[float].
            len_: the length of the returning list.
        Returns:
            a list of sampled gadgets
        """
        # group w.r.t. the energy
        grouped = self._group_energies(energies)
        sampled = []
        for _, gadgets in grouped:
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
        self, energies: list[float], minlen: int, maxlen: int, _changes: int = 3
    ) -> list[APIGadget]:
        """Sample and mutate the API combination from the harness banks.
        Args:
            energies: a list of the energies, that order of `self.gadgets`.
            minlen, maxlen: the minimum/maximum length of a api list.
            _changes: the number of the inserted/replaced gadgets.
        Returns:
            the list of mutated seeds
        """
        (seed,) = random.choices(
            self.seeds,
            [q["quality"] for q in self.seeds.values()],
            k=1,
        )
        names = set(self.seeds[seed]["critical_path"])
        gadgets = [(g, e) for g, e in zip(self.gadgets, energies) if g.name in names]
        # TODO: mutator
        match random.randint(3):
            case 0:  # insert
                return self._insert(gadgets, maxlen, _changes)
            case 1:  # replace
                gadgets = self._remove(gadgets, _changes)
                return self._insert(gadgets, maxlen, _changes)
            case 2:  # crossover
                pass

    def _insert(
        self,
        gadgets: list[tuple[APIGadget, float]],
        energies: list[float],
        maxlen: int,
        k: int,
    ) -> list[APIGadget]:
        """Insert the k-gadgets of highest energies.
        Args:
            gadgets: the target gadgets and their energies.
            energies: the list of energies, that order of `self.gadgets`.
            maxlen: the maximum length of the gadgets.
            k: the number of the gadgets to insert.
        Returns:
            inserted gadgets.
        """
        gadgets = {g.signature(): g for g, _ in gadgets}
        # group the energies
        grouped = self._group_energies(energies)
        for _, _gadgets in grouped:
            random.shuffle(_gadgets)
        # unpack
        candidates = [gadget for _, _gadgets in grouped for gadget in _gadgets]
        while len(gadgets) < maxlen and k > 0:
            gadget, *candidates = candidates
            if gadget.signature() in gadgets:
                continue
            gadgets[gadget.signature()] = gadget
            k -= 1
        return list(gadgets.values())

    def _remove(
        self, gadgets: list[tuple[APIGadget, float]], k: int
    ) -> list[APIGadget]:
        """Remove the k-gadgets of lowest energies.
        Args:
            gadgets: a list of target gadgets and their energies.
            k: the number of the gadgets to remove.
        Returns:
            removed gadgets.
        """
        lowest = set(
            gadget.signature()
            for gadget in self._highest_energies(gadgets, len(gadgets))[-k:]
        )
        return [gadget for gadget, _ in gadgets if gadget.signature() not in lowest]

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
