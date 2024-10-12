import multiprocessing as mp
import os
import shutil
import subprocess
import tempfile
from time import time
from typing import Iterator

from agentfuzz.analyzer import Coverage, Fuzzer
from agentfuzz.language.cpp.lcov import parse_lcov


class LibFuzzer(Fuzzer):
    """Libfuzzer wrapper."""

    def __init__(
        self,
        path: str,
        libpath: str,
        minimize_corpus: bool = True,
        _workdir: str | None = None,
    ):
        """Initialize the fuzzer wrapper.
        Args:
            path: a path to the executable file.
            libpath: a path to the library for tracking the coverage.
            minimize_corpus: minimize the corpus if given is True, using a `-merge=1` option.
            _workdir: a path to the working directory, use `{os.path.dirname(path)}` if it is not provided.
        """
        self.path = path
        self.libpath = libpath
        self.minimize_corpus = minimize_corpus
        self._workdir = _workdir or os.path.dirname(self.path)
        # for supporting parallel run
        self._proc: subprocess.Popen | None = None
        self._timeout: float | None = None

    def minimize(self, corpus_dir: str, outdir: str | None = None) -> str | None:
        """Minimize the corpus with a `-merge=1` option.
        Args:
            corpus_dir: a path to the directory containing fuzzing inputs (corpus).
            outdir: a path to the directory to write a minimized corpus.
                assume it as `os.path.join(self._workdir, f"{os.path.basename(corpus_dir)}_min)"` if it is not provided.
        Returns:
            a path to the directory where minimized corpus is written.
                None if minimizing process is failed.
        """
        outdir = outdir or os.path.join(
            self._workdir, f"{os.path.basename(corpus_dir)}_min"
        )
        os.makedirs(outdir, exist_ok=True)
        # specify artifact directory
        _artifact_dir = os.path.join(self._workdir, "artifact")
        os.makedirs(_artifact_dir, exist_ok=True)
        with open(f"{self.path}.minimize.log", "wb") as f:
            run = subprocess.run(
                [
                    self.path,
                    "-merge=1",
                    outdir,
                    corpus_dir,
                    f"-artifact_prefix={_artifact_dir}/",
                ],
                stdout=subprocess.DEVNULL,
                stderr=f,
                env={**os.environ, "LD_PRELOAD": self.libpath},
            )
        try:
            run.check_returncode()
        except subprocess.CalledProcessError:
            return None
        return outdir

    def run(
        self,
        corpus_dir: str | None = None,
        fuzzdict: str | None = None,
        wait_until_done: bool = False,
        timeout: float | None = 300.0,
        runs: int | None = None,
        _profile: str | None = None,
        _logfile: str | None = None,
        _isolate_copurs_dir: bool = False,
    ) -> int | Exception | None:
        """Run the compiled harness with given corpus directory and the fuzzer dictionary.
        Args:
            corpus_dir: a path to the directory containing fuzzing inputs (corpus).
            fuzzdict: a path to the fuzzing dictionary file.
            wait_until_done: wait for the fuzzer done.
            timeout: the maximum running time in seconds.
            runs: the number of individual tests, None or -1 for indefinitely run.
            _profile: a path to the coverage profiling file, use `{self.path}.profraw` if it is not provided.
            _logfile: a path to the fuzzing log file, use `{self.path}.log` if it is not provided.
            _isolate_corpus_dir: whether isolate the corpus directory or not.
        Returns:
            int: return code of the fuzzer process.
            None: if fuzzer process is running now.
            Exception: if the fuzzer process deos not exist or timeout occured.
        """
        assert not wait_until_done or (
            timeout is not None or runs is not None
        ), "hang may occur"
        # if already run
        if self._proc is not None:
            return self.poll()
        # isolate the corpus directory
        if corpus_dir is not None:
            if self.minimize_corpus:
                # if successfully minimized
                if minimized := self.minimize(corpus_dir):
                    if _isolate_copurs_dir:
                        corpus_dir = minimized
                    else:
                        shutil.rmtree(corpus_dir)
                        shutil.move(minimized, corpus_dir)
            elif _isolate_copurs_dir:
                # since libfuzzer generate the new corpus inplace the directory
                _new_dir = os.path.join(self._workdir, "corpus")
                shutil.copytree(corpus_dir, _new_dir)
                corpus_dir = _new_dir
        # prepare the arguments
        _artifact_dir = os.path.join(self._workdir, "artifact")
        os.makedirs(_artifact_dir, exist_ok=True)
        cmd = [self.path, f"-artifact_prefix={_artifact_dir}/"]
        if corpus_dir is not None:
            cmd.append(corpus_dir)
        if fuzzdict is not None:
            cmd.append(f"-dict={fuzzdict}")
        if runs is not None:
            cmd.append(f"-runs={runs}")
        # remove if profile exists
        _profile = _profile or f"{self.path}.profraw"
        if os.path.exists(_profile):
            os.remove(_profile)
        # run the fuzzer
        self._proc = subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=open(_logfile or f"{self.path}.log", "wb"),
            env={
                **os.environ,
                "LLVM_PROFILE_FILE": _profile,
                "LD_PRELOAD": self.libpath,
            },
        )
        if timeout is not None:
            self._timeout = time() + timeout
        if not wait_until_done:
            return None
        # wait until done
        try:
            self._proc.wait(timeout)
        except subprocess.TimeoutExpired:
            pass
        # return code
        retn = self.poll()
        # hard clear (for preventing process miss-clear)
        self.clear()
        return retn

    def batch_run(
        self,
        corpus_dirs: list[str],
        batch_size: int,
        fuzzdict: str | None = None,
        timeout: float | None = 300,
        runs: int | None = None,
        return_cov: bool = True,
    ) -> Iterator[tuple[str, int | Exception, tuple[Coverage, Coverage] | None]]:
        """Run the compiled harness in batch.
        Args:
            corpus_dirs: a list of corpus directories.
            batch_size: the desired concurrency level, maybe a size of the batch, or the number of the process.
            fuzzdict: a path to the fuzzing dictionary file.
            timeout: the maximum running time in seconds, None or indefinitely run.
            runs: the number of individual tests, None for indefinitely run.
            return_cov: whether return the coverage descriptors or not.
        Returns:
            str: a path to the corpus directory.
            int | Exception: the return code or the exceptions during run the fuzzer.
            tuple[Coverage, Coverage]: the coverage descriptors about library and fuzzer-itself.
        """
        with mp.Pool(batch_size) as pool:
            yield from pool.imap_unordered(
                _batch_run_proxy,
                [
                    (self, corpus_dir, fuzzdict, timeout, runs, return_cov)
                    for corpus_dir in corpus_dirs
                ],
                chunksize=batch_size * 2,
            )

    def poll(self) -> int | None | Exception:
        """Poll the return code of the fuzzer process and clear if process done.
        Returns:
            int: return code of the fuzzer process.
            None: if fuzzer process is running now.
            Exception: if the fuzzer process deos not exist or timeout occured.
        """
        if self._proc is None:
            return RuntimeError("process is not running now")
        # if the process is running and before timeout
        if (retn := self._proc.poll()) is None and time() < self._timeout:
            return None
        # clear
        self.clear()
        # return code if exists. otherwise, return timeouterror
        return (
            retn
            if isinstance(retn, int)
            else TimeoutError(f"fuzzer process {self.path} timeout")
        )

    def halt(self) -> int | Exception:
        """Stop the fuzzer.
        Returnss:
            int: return code of the fuzzer proces.
            Exception: if the fuzzer process does not exist or timeout occured.
        """
        if (retn := self.poll()) is not None:
            return retn
        # kill the process
        self.clear()
        return TimeoutError(f"fuzzer process {self.path} timeout")

    def clear(self):
        """Clear the fuzzing process (kill the process if it is running)."""
        if self._proc is None:
            return
        if self._proc.poll() is None:
            self._proc.kill()
        if self._proc.stdout is not None:
            self._proc.stdout.close()
        self._proc, self._timeout = None, None

    def track(self, _logfile: str | None = None) -> int | float:
        """Monitor the coverage generated by the running fuzzer.
        Args:
            _logfile: a path to the log file, assume it as f"{self.path}.log` if it is not provided.
        Returns:
            the meausre of current coverage.
        """
        # assign default value
        _logfile = _logfile or f"{self.path}.log"
        with open(_logfile, errors="replace") as f:
            log = f.read()
        # `#614201 REDUCE cov: 253 ft: 1249 corp: 455/35kb lim: 1188 exec/s: 153550 rss: 493Mb L: 520/1003 MS: 1 EraseBytes-`
        index = log.rfind("cov")
        if index == -1:
            return 0
        _, cov, _ = log[index:].split(maxsplit=2)
        return int(cov)

    def coverage(
        self,
        itself: bool = False,
        target: str | None = None,
        _profile: str | None = None,
        _remove_previous_profdata: bool = True,
    ) -> Coverage:
        """Collect the coverage w.r.t. the given library.
        Args:
            itself: whether compute the branch coverage of the harness itself or target library.
            target: a path to the target library.
                if it is not provided, assume it as `self.libpath` if `not itself`, otherwise `self.path`.
            _profile: a path to the coverage profiling file, assume it as f"{self.path}.profraw" if it is not provded.
        Returns:
            collected coverage.
        """
        # assign default value
        _profile = _profile or f"{self.path}.profraw"
        _merged = _profile.replace(".profraw", ".profdata")
        if os.path.exists(_merged) and _remove_previous_profdata:
            os.remove(_merged)
        # merge the raw profile
        try:
            run = subprocess.run(
                ["llvm-profdata", "merge", "-sparse", _profile, "-o", _merged],
                capture_output=True,
            )
            run.check_returncode()
        except subprocess.CalledProcessError as e:
            raise RuntimeError(
                f"failed to merge the raw profile data `{_profile}` to `{_merged}`: {run.stderr}"
            ) from e
        # return the coverage
        cov: dict
        try:
            run = subprocess.run(
                [
                    "llvm-cov",
                    "export",
                    target or (self.path if itself else self.libpath),
                    "-format=lcov",
                    f"--instr-profile={_merged}",
                ],
                capture_output=True,
            )
            run.check_returncode()
            cov = parse_lcov(run.stdout.decode("utf-8"))
        except subprocess.CalledProcessError as e:
            raise RuntimeError(
                f"failed to extract the coverage from the profile data `{_merged}`: {run.stderr}"
            ) from e
        except Exception as e:
            raise RuntimeError(
                f"failed to parse the lcov-format coverate data from profile `{_merged}`: {e}"
            ) from e
        # pack to coverage
        packed = Coverage()
        for filename, filelevel in cov.items():
            packed.merge(
                Coverage(
                    functions={
                        fn: {
                            f"L{lineno}#({blockno}, {branchno})": hit or 0
                            for lineno, branches in info["branches"].items()
                            for (blockno, branchno), hit in branches.items()
                        }
                        for fn, info in filelevel["functions"].items()
                    },
                    lines={
                        os.path.abspath(filename): {
                            str(lineno): hit
                            for lineno, hit in filelevel["lines"].items()
                        }
                    },
                )
            )
        return packed


def _batch_run_proxy(
    args: tuple[LibFuzzer, str, str | None, float | None, int | None, bool]
):
    # unpack
    fuzzer, corpus_dir, fuzzdict, timeout, runs, return_cov = args
    # clone for seperating working directory
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as _workdir:
        fuzzer = LibFuzzer(
            fuzzer.path,
            fuzzer.libpath,
            fuzzer.minimize_corpus,
            _workdir=_workdir,
        )
        _profile = os.path.join(fuzzer._workdir, "default.profraw")
        # run the fuzzer
        try:
            retn = fuzzer.run(
                corpus_dir,
                fuzzdict,
                wait_until_done=True,
                timeout=timeout,
                runs=runs,
                _profile=_profile,
                _logfile=os.path.join(fuzzer._workdir, "log"),
            )
        except Exception as e:
            return corpus_dir, e, None

        if not return_cov:
            return corpus_dir, retn, None
        # extract coverage
        try:
            cov_lib = fuzzer.coverage(_profile=_profile)
            cov_fuz = fuzzer.coverage(itself=True, _profile=_profile)
        except Exception as e:
            return corpus_dir, e, None

    return corpus_dir, retn, (cov_lib, cov_fuz)
