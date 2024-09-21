# agent-fuzz
Python implementation of LLM Agent-based fuzz-driver generation 

## Prepare

For mac
```
brew install universal-ctags
brew install global
```

For Ubuntu
```
sudo apt-get install -y global universal-ctags
```

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

- [ ] Initial generation pipeline
- [ ] Energy/Density measure supports (ref:PromptFuzz)
- [ ] API scheduler
- [ ] Fuzzer-run / harness-generation scheduler
- [ ] Agentic fuzz-driver generation

### Coverage feedback to fuzz-driver
