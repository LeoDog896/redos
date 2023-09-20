# Detection

In order to do efficient code scanning, redos uses [swc](https://swc.rs/) to parse JS/TS files.

## Vulnerable Regex Patterns

(Base Identification Information from [ReDoSHunter](https://www.usenix.org/conference/usenixsecurity21/presentation/li-yeting))

If you want to play around with these, [`regex101`](https://regex101.com/) has a great debugging tool to test these out step by step.

For a regex to be vulnerable to ReDoS in general, we first immideately filter for:
- Contains an terminal token, so that way the regex doesn't match (forcing the regex to do backtracking)
    - Thus we can immideately scan for regexes that contain a modifier, but don't end with it (e.g. `a+$`)

### Initial Overlapping Disjunction

- There are at least two alternations in the group that share a common token (e.g. `(token|tokenq)+`)
    - There can be >2 alternations, and the others don't need to share a common token
- The overlapping disjunction can be reached as the first token in the regex

Small example: `(a|a)+$`

Complexity: `O(2^n)` (exponential)

### Nested Quantifier

- A substantial quantifier is present inside any group that also is modified by a substantial quantifier

Small example: `(a+)+$`

Complexity: `O(2^n)` (exponential)

### Exponential Overlapping Adjacency

- 2 tokens with big quantifiers are present in the group, and overlap

Small example: `((a)(a+))+$`

Complexity: `O(2^n)` (exponential)


### Polynomial Overlapping Adjacency

- 2 tokens with big quantifiers are present in the group, and overlap
- The group doesn't need a big quantifier (e.g. `?` would work fine)

Small example: `(a+a+)?$`

Complexity: `O(n^2)` (polynomial)

### Initial Large Quantifier

- A quantifier is present in the regex with a substantial upper bound
- The token that the quantifier is attatched to can be reached as the first token in the regex

Small example: `a+$`

Complexity: `O(n^2)` (polynomial)

## Analysis

We do AST scanning for regexes that match the above patterns.
