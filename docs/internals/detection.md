# Detection

In order to do efficient code scanning, redos uses [swc](https://swc.rs/) to parse JS/TS files.

## Vulnerable Regex Patterns

(Base Identification Information from [ReDoSHunter](https://www.usenix.org/conference/usenixsecurity21/presentation/li-yeting))

If you want to play around with these, [`regex101`](https://regex101.com/) has a great debugging tool to test these out step by step.

For a regex to be vulnerable to ReDoS in general, we first immideately filter for:
- Contains an terminal token, so that way the regex doesn't match (forcing the regex to do backtracking)
    - Thus we can immideately scan for regexes that contain a modifier, but don't end with it (e.g. `a+$`)

### Overlapping Disjunction

- There are at least two alternations in the group that share a common token (e.g. `(token|tokenq)+`)
    - There can be >2 alternations, and the others don't need to share a common token

Small example: `(a|a)+$`

Complexity: `O(2^n)` (exponential)

### Nested Quantifier

- A quantifier is present inside a group

Small example: `(a+)+$`

Complexity: `O(2^n)` (exponential)

### Prefix Node with Quantifier

- A quantifier is present in the regex with a substantial upper bound
- The token that the quantifier is attatched to is the first token in the regex

Small example: `a+$`

Complexity: `O(n^2)` (k degree polynomial for every token with a quantifier)

## Analysis

We do AST scanning for regexes that match the above patterns.
