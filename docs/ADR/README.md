# Architecture Decision Records

ADRs record accepted implementation decisions at the source identity and scope
stated by each file. They are not alternate Architecture books, current support
claims, milestone reports, or instructions to resume an old branch.

Use an ADR only when:

- the current canonical pair still permits the decision;
- current source still has the named owner and boundary;
- no later ADR, issue, contract, or `main` change supersedes it;
- the current work unit names the affected decision explicitly.

An ADR may explain why code has its present shape. It cannot prove that the
mechanism is installed, running, verified, or valuable. New ADRs are required
only for a load-bearing default, authority/state owner, Kernel hard dependency,
canonical format/protocol, Architecture deviation, or promotion of an
experiment to production default. Ordinary implementation belongs in the owning
issue/PR and source tests.
