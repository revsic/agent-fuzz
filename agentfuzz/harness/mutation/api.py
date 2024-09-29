import json
import random

from agentfuzz.analyzer import APIGadget, Coverage


class APIMutator:
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
        self.seeds = seeds or []
        self.exponent = exponent

    def append_seeds(
        self,
        path: str,
        cov: Coverage,
        critical_path: list[tuple[str | APIGadget, int | None]],
    ):
        """Compute append a harness seed into the seed pool.
        Args:
            path: a path to the harness source code.
            cov: the branch coverage of the given harness.
            critical_path: the extracted critical path from the harness.
        """
        # TODO: Compute density
        density = 1.0
        unique_branches = len(cov.flat(nonzero=True))
        quality = density * (1 + unique_branches)
        _name = lambda g: (g if isinstance(g, str) else g.name)
        self.seeds.append(
            {
                "quality": quality,
                "critical_path": [
                    (_name(gadget), lineno) for gadget, lineno in critical_path
                ],
                "source": path,
            }
        )

    def select(self, coverage: Coverage, minlen: int, maxlen: int) -> list[APIGadget]:
        """Select the APIs w.r.t. the energies and qualities.
        Args:
            coverage: a list of API coverages.
            minlen, maxlen: the minimum/maximum length of a api list.
        Returns:
            a list of selected apis.
        """
        energies = self._energy(coverage)
        # from PromptFuzz
        det = min(len(self.seeds) / 100, 0.8) > random.random()
        if len(self.seeds) > 0 and det:
            return self._mutate_from_seeds(energies, minlen, maxlen)
        # load the highest energies
        return self._highest_energies(energies, maxlen)

    def converge(self) -> bool:
        """Check the mutation convergence.
        Returns:
            True if the mutation policy converges.
        """
        # trivial case
        return False

    def dump(self) -> dict:
        """Serialize the states of mutator into the single dictionary.
        Returns:
            the states of mutator.
        """
        return {
            "gadgets": [g.dump() for g in self.gadgets],
            "counter": self.counter,
            "seeds": self.seeds,
            "exponent": self.exponent,
        }

    @classmethod
    def load(cls, dumps: str | dict) -> "APIMutator":
        """Load from the state.
        Args:
            dumps: the dumped states from the method `APIMutator.dump`.
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
            exponent=dumps["deponent"],
        )

    ##### internal methods

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
        gadgets = self._sample_apis_from_seeds(energies)
        match random.randint(0, 2):
            case 0:  # insert
                return self._insert(gadgets, energies, maxlen, _changes)
            case 1:  # replace
                gadgets = self._remove(gadgets, _changes)
                return self._insert(gadgets, energies, maxlen, _changes)
            case 2:  # crossover
                other = self._sample_apis_from_seeds(energies)
                return self._crossover(gadgets, other, _changes)

    def _sample_apis_from_seeds(
        self, energies: list[float]
    ) -> list[tuple[APIGadget, float]]:
        """Sample a seed from seeds and convert it to a list of APIs.
        Returns:
            a list of API and their energies.
        """
        pack = {
            gadget.name: (gadget, energy)
            for gadget, energy in zip(self.gadgets, energies)
        }
        (seed,) = random.choices(
            self.seeds,
            [seed["quality"] for seed in self.seeds],
            k=1,
        )
        # TODO: It may occur unexpected behaviour on overloadable language
        names, gadgets = set(), []
        for name, _ in seed["critical_path"]:
            if isinstance(name, APIGadget):
                name = name.name
            if name in names or name not in pack:
                continue
            gadgets.append(pack[name])
            names.add(name)
        return gadgets

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
        gadgets = [g for g, _ in gadgets]
        _cache = {g.signature() for g in gadgets}
        # group the energies
        grouped = self._group_energies(energies)
        for _, _gadgets in grouped:
            random.shuffle(_gadgets)
        # unpack
        candidates = [gadget for _, _gadgets in grouped for gadget in _gadgets]
        while len(gadgets) < maxlen and k > 0:
            gadget, *candidates = candidates
            if gadget.signature() in _cache:
                continue
            _cache.add(gadget.signature())
            gadgets.insert(random.randint(0, len(gadgets)), gadget)
            k -= 1
        return gadgets

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

    def _crossover(
        self,
        gadgets: list[tuple[APIGadget, float]],
        other: list[tuple[APIGadget, float]],
        k: int,
    ) -> list[APIGadget]:
        """Cross-over the gadgets.
        Args:
            gadgets, other: a list of target gadgets and their energies.
            k: the number of the gadgets to replace.
        Returns:
            crossed-gadgets.
        """
        # on a longer baseline
        if len(gadgets) < len(other):
            gadgets, other = other, gadgets
        # if both are shorter than k
        if len(gadgets) < k:
            return gadgets + other
        # if shorter one is shorter than k
        if len(other) < k:
            i = random.randint(0, len(gadgets) - len(other) - 1)
            return gadgets[:i] + other + gadgets[i + len(other) :]
        # if both are longer than k
        i = random.randint(0, len(gadgets) - k - 1)
        j = random.randint(0, len(other) - k - 1)
        return gadgets[:i] + other[j : j + k] + gadgets[i + k :]

    def _energy(self, coverage: Coverage) -> list[float]:
        """Compute the energy for scheduling the api mutation.
        Args:
            coverage: a list of API coverages.
        Returns:
            list of energies that order of `self.gadgets`.
        """

        def _energy(cov: float, seed: int, prompt: int) -> float:
            return (1 - cov) / ((1 + seed) * (1 + prompt)) ** self.exponent

        return [
            _energy(coverage.cover_branch(g.name) or 0.0, cnt["seed"], cnt["prompt"])
            for g in self.gadgets
            if (cnt := self.counter[g.signature()])
        ]
