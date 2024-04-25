# Vulnerable Regex Patterns

(Base Identification Information from [ReDoSHunter](https://www.usenix.org/conference/usenixsecurity21/presentation/li-yeting))

If you want to play around with these, [`regex101`](https://regex101.com/) has a great debugging tool to test these out step by step.

For a regex to be vulnerable to ReDoS in general, we first immediately filter for:

- Contains an terminal token, so that way the regex doesn't match (forcing the regex to do backtracking)
  - Thus we can immideately scan for regexes that contain a modifier, but don't end with it (e.g. `a+$`)

## Vulnerabilities

### Exponential Overlapping Disjunction

- There are at least two alternations in the group that share a common token (e.g. `(token|tokenq)+`)
  - There can be >2 alternations, and the others don't need to share a common token
- The overlapping disjunction can be reached as the first token in the regex

Small example: `b(a|a)+$`

Complexity: `O(2^n)` (exponential)

### Nested Quantifier

- A substantial quantifier is present inside any group that also is modified by a substantial quantifier

Small example: `b(a+)+$`

Complexity: `O(2^n)` (exponential)

### Exponential Overlapping Adjacency

- 1 tokens with a big quantifier and one with none is present in the group, and overlap

Small example: `b(aa+)+$`

Complexity: `O(2^n)` (exponential)

### Polynomial Overlapping Adjacency

- 2 tokens with big quantifiers are present in the group, and overlap

Small example: `b(a+a+)$`

Complexity: `O(n^2)` (polynomial)

### Initial Large Quantifier

- A quantifier is present in the regex with a substantial upper bound
- The token that the quantifier is attatched to can be reached as the first token in the regex

Small example: `a+$`

Complexity: `O(n^2)` (polynomial)
