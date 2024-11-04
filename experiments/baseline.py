import json
import os
from datetime import datetime, timedelta, timezone

from agentfuzz.harness import AgenticHarnessGenerator
from agentfuzz.language import CppSupports


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("--target", default="cjson")
    parser.add_argument("--stamp", default=None)
    parser.add_argument("--check-only", default=False, action="store_true")
    args = parser.parse_args()
    # target project
    benchmark = os.path.abspath(f"{__file__}/../../benchmark/{args.target}")
    # construct project
    stamp = args.stamp or datetime.now(timezone(timedelta(hours=9))).strftime(
        "%Y.%m.%dT%H:%M"
    )
    workdir = f"./workspace/{args.target}/{stamp}"
    os.makedirs(workdir, exist_ok=True)
    # load config
    config = CppSupports._Config.load_from_yaml(os.path.join(benchmark, "config.yaml"))
    config.srcdir = os.path.join(benchmark, config.srcdir)
    if config.fuzzdict is not None:
        config.fuzzdict = os.path.join(benchmark, config.fuzzdict)
    if config.corpus_dir is not None:
        config.corpus_dir = os.path.join(benchmark, config.corpus_dir)
    if config.libpath is not None:
        config.libpath = os.path.join(benchmark, config.libpath)
    config.include_dir = [os.path.join(benchmark, dir_) for dir_ in config.include_dir]
    project = CppSupports(workdir, config)
    checked = project.precheck(_hook=True, _errfile=f"{workdir}/precheck.failed")
    with open(os.path.join(workdir, "prechecked.json"), "w") as f:
        json.dump([api.dump() for api in checked], f, indent=2, ensure_ascii=False)

    if args.check_only:
        print(f"Prechecked, possible APIs: {len(checked)}")
    else:
        generator = AgenticHarnessGenerator(
            project.factory,
            project.workdir,
            logger=os.path.join(workdir, "harness-gen.log"),
            _agent_logger=os.path.join(workdir, "agent.log"),
            _valid_logger=os.path.join(workdir, "validator.log"),
        )
        generator.logger.log(f"Prechecked, possible APIs: {len(checked)}")
        generator.run(load_from_state=True)
