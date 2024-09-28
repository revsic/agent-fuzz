# agent-fuzz
Python implementation of LLM Agent-based fuzz-driver generation 

## Usage

For mac
```bash
brew install universal-ctags
brew install global
brew install llvm
brew install graphviz
```

For Ubuntu
```bash
sudo apt-get install -y global universal-ctags graphviz llvm
```

Install the agentfuzz
```bash
git clone https://github.com/revsic/agent-fuzz
cd agent-fuzz && pip install .
```

Prepare the project, reference sample [benchmark/cjson/build](./benchmark/cjson/build.sh) script.
```bash
cd benchmark/cjson
bash build.sh
# project structure
# | workspace
#   | src (required)
#     | cJSON (repo)
#   | build
#   | lib (required)
#     | libcjson.a
#   | include (optional)
#     | cJSON.h
#   | corpus (optional)
#   | dict (optional)
#     | json.dict
```

Run the agent fuzz, reference sample [benchmark/cjson/config](./benchmark/cjson/config.yaml)
```bash
cd benchmark/cjson
OPENAI_API_KEY=$YOUR_API_KEY_HERE python -m agentfuzz \
    --language cpp \
    --workdir workspace/agentfuzz \
    --config config.yaml
```

[TODO] Visualize the fuzzing results

## Roadmap

### OSS-Fuzz Build Script supports

Benchmark

- [x] cJSON
- [ ] libpcap
- [ ] libxml2

### Fuzz-driver generation loop

Static analysis

- [x] Clang AST parser supports
- [x] Collect API function/type gadgets
- [ ] Infer input constraints 
- [x] Critical path extraction

Dynamic analysis

- [x] Compile the harness
- [x] Run the fuzzer
- [x] Compute the branch coverage

FP Elimination
- [x] Runtime fuzzing validation: 60sec for cov growth, 600sec for corpus pool
- [x] Runtime coverapge validation: critical path check
- [x] Corpus reusage

Agentic Fuzz-driver generation

- [x] Initial generation pipeline
- [x] Energy measure supports (ref:PromptFuzz)
- [ ] Density measure supports
- [x] API scheduler
- [ ] Fuzzer-run / harness-generation scheduler
- [ ] Agentic fuzz-driver generation
- [x] State load and dump supports
- [ ] Fuzzer fuser
- [ ] Multiprocessing Support
