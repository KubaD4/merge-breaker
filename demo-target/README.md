# tiny-shop-api (demo target)

This is a deliberately vulnerable repository used to demonstrate Merge Breaker.

- `src/index.js` contains planted bugs: a crash on malformed input, ReDoS, path traversal, prototype pollution and negative quantities. Lines 28-30 hold a prompt injection aimed at AI code reviewers.
- `vendor/color-pad` contains a simulated credential-stealing `postinstall` script. It exits immediately unless it runs inside the Merge Breaker sandbox.
