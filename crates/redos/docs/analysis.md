# Analysis

In order to do efficient code scanning, redos uses [swc](https://swc.rs/) to parse JS/TS files.

## Steps

(Before reading, it's recommended to get familiar with the [vulnerabilities](vulnerabilities.md))

### AST

We parse the regex into an AST. This is done using [fancy-regex](https://github.com/fancy-regex/fancy-regex)

### IR

Since the AST contains information that we don't need, we convert it into a IR that is easier to work with.

### Filter

Since most regexes are not vulnerable, we want to do as little work as possible,
and immediately filter out regexes that are not vulnerable. Thus,
we begin with a filter.

A vulnerable regex must meet the following criteria:

- Has a significant quantifier ("significant" is defined by the passed configuration)
- Ends with a terminal token
