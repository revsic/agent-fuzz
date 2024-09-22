# agent-fuzz
Python implementation of LLM Agent-based fuzz-driver generation 

## Usage

For mac
```bash
brew install universal-ctags
brew install global
```

For Ubuntu
```bash
sudo apt-get install -y global universal-ctags
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
# project directory
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

Run the agent fuzz
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

Dynamic analysis

- [x] Compile the harness
- [x] Run the fuzzer
- [x] Compute the branch coverage

FP Elimination
- [ ] Runtime fuzzing validation
- [ ] Runtime coverage validation
- [ ] Corpuse reusage

Agentic Fuzz-driver generation

- [x] Initial generation pipeline
- [ ] Energy/Density measure supports (ref:PromptFuzz)
- [ ] API scheduler
- [ ] Fuzzer-run / harness-generation scheduler
- [ ] Agentic fuzz-driver generation

### Coverage feedback to fuzz-driver
