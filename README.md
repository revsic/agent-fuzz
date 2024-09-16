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

Agentic Fuzz-driver generation

- [ ] Initial generation pipeline
- [ ] Energy/Density measure supports (ref:PromptFuzz)
- [ ] Non-agentic fuzz-driver generation
- [ ] Agentic fuzz-driver generation

### Coverage feedback to fuzz-driver
