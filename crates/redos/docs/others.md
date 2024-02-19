# Other Tools

Current known list of proper redos detectors and their weaknesses:

> **Note**: This list is not exhaustive, and is subject to change.

- [regexploit](https://github.com/doyensec/regexploit), which detects ambiguities where characters can be matched by multiple subpatterns.
  - This tool has false negatives, which is dangerous. (e.g. `(a|aa)+$` is not detected)
- [rat](https://github.com/parof/rat), which detects ReDoS by making many "overmatching" strings for regexes.
  - This tool doesn't work with lookarounds and backreferences.
- [recheck](https://github.com/makenowjust-labs/recheck), which detects ReDoS by using a genetic algorithm to generate strings that cause ReDoS (combination of dynamic and static analysis).
  - This tool, while potentially the most accurate, is excruciatingly slow.
- [redos-detector](https://github.com/tjenkinson/redos-detector), which detects the number of possible backtracks
  - Doesn't detect 2nd degree ReDoS
