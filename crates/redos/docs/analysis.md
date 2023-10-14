# Analysis

In order to do efficient code scanning, redos uses [swc](https://swc.rs/) to parse JS/TS files.

We use [nom](https://github.com/rust-bakery/nom) to parse the regex. The goal is to
have barely any immideate representation, and find vulnerabilities
as we parse the regex. 

## Steps

(Before reading, it's reccomended to get familiar with the [vulnerabilities](vulnerabilities.md))

Since most regexes are not vulnerable, we want to do as little work as possible,
and immideately filter out regexes that are not vulnerable. Thus,
we begin with a filter.

### Filter

Every vulnerable regex has some sort of non-trivial quantifier, so we search for the following characters:

- `*`
- `+`
- `{`

(We don't search for `?` because it's a trivial quantifier)

### IR Generation

When we parse a regular expression, we don't make a full AST. Instead, we make a
IR that is a parent-child tree of the attack strings.

For example, given [^abc](123), parsing it would return:

```text
Root
├── \0
├── 123
```

which is a representation of what we need to do to match the regex.

This also stores information on different alternate paths and quantifiers,
allowing us to detect vulnerabilities.
