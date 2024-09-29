import os
from datetime import datetime
from agentfuzz.language import CppSupports


if __name__ == "__main__":
    # target project
    _mother = os.path.abspath(f"{__file__}/../..")
    build = os.path.abspath(f"{_mother}/benchmark/cjson/workspace")
    # construct project
    workdir = f"./workspace/{datetime.now().strftime('%Y.%m.%dT%H:%M')}"
    project = CppSupports(
        workdir,
        CppSupports._Config(
            name="cjson",
            srcdir=f"{build}/src/cJSON",
            corpus_dir=f"{build}/corpus",
            fuzzdict=f"{build}/dict/json.dict",
            libpath=f"{build}/lib/libcjson.a",
            include_dir=[f"{build}/include"],
            timeout=60,
            timeout_unit=10,
        ),
    )
    project.run(
        load_from_state=False,
        logger=os.path.join(workdir, "harness-gen.log"),
    )
