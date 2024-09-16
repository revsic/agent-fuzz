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

### Fuzz-driver generation loop

Static analysis

- [x] Clang AST parser supports
- [x] Collect API function/type gadgets
- [ ] Infer input constraints 

Dynamic analysis

- [ ] Compile the harness
- [ ] Run the fuzzer
- [ ] Compute the branch coverage

Agentic Fuzz-driver generation

- [ ] Initial generation pipeline
- [ ] Energy/Density measure supports (ref:PromptFuzz)
- [ ] API scheduler
- [ ] Fuzzer-run / harness-generation scheduler
- [ ] Agentic fuzz-driver generation

### Coverage feedback to fuzz-driver
