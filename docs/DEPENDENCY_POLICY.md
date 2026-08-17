# Dependency policy

## Licensing posture

### 1. Definitions

**"the Work"** means the source code, schemas, documentation and build
configuration authored for ELIOT and contained in this repository.

**"Separately Licensed Component"** means any third-party program, service or
data store that the Work interoperates with at runtime, that is obtained by the
operator independently of the Work, and that is governed by its own licence.
SurrealDB is presently such a component.

### 2. Licence of the Work

The Work is licensed under the MIT Licence, as set out in the `LICENSE` file at
the root of this repository. That grant is unconditional and is not qualified,
narrowed or superseded by any provision of this policy. Nothing in this
document adds a term to, or removes a term from, the MIT grant.

Any contribution accepted into the Work is accepted on the same terms.

### 3. Separately Licensed Components are optional

No Separately Licensed Component is a part of the Work.

Each such component is an interchangeable implementation of a capability the
Work defines in the abstract. The Work does not treat any particular vendor,
product or protocol implementation as a fixed architectural commitment, and the
substitution of one component for another — including replacement of the
canonical data store — is an anticipated and supported evolution rather than a
breaking exception.

Accordingly, the Work:

1. does not vendor, embed, bundle or redistribute any Separately Licensed
   Component, in source or binary form;
2. does not incorporate any portion of such a component into its own
   distribution or build output; and
3. does not require the operator to obtain any such component from the
   authors of the Work.

The operator obtains, installs and licenses such components directly and
remains responsible for compliance with the terms applicable to them.

### 4. Integration occurs at an independent protocol boundary

Where the Work interoperates with a Separately Licensed Component, it does so
across a network protocol boundary, using a transport implemented in the Work
itself and specified independently of that component's own client libraries.

This is a deliberate architectural constraint, not an incidental one. The
canonical data store is reached over a WebSocket/RPC transport authored within
the Work rather than through a vendor-supplied SDK. One consequence is a
reduced and more clearly delineated dependency surface; another is that the
capability may be re-pointed at a different implementation of the same
protocol, or at a different protocol, without redesign of the Work.

The Work links no Separately Licensed Component, statically or dynamically.

### 5. Selection preference

Where a capability can be satisfied by more than one component, the Work
prefers, in order:

1. components distributed under permissive open-source licences;
2. components implementing an open, independently specified protocol for which
   more than one implementation exists;
3. components whose terms permit unrestricted downstream use of the Work.

Where a capability can presently be satisfied only by a component that does not
meet these preferences, the Work will document that fact plainly and will treat
the provision of a conforming alternative as outstanding work rather than as a
settled position.

### 6. Alternatives

The Work aims to offer, for each capability that depends on a Separately
Licensed Component, at least one alternative implementation or a documented
migration path, such that no operator is compelled to accept terms they decline.

### 7. Endpoints

Where an external service is used, the Work prefers endpoints that are
independently addressable and independently specified, so that the Work's own
distribution and use are not made subject to terms attaching to a particular
provider's client software or service integration.

### 8. Scope of this statement

This document states the engineering and licensing policy of the project. It is
a description of intent and of architectural fact. It is not legal advice, it
is not a warranty, and it makes no representation as to the effect of any
third-party licence.

Before any public distribution, packaging or redistribution arrangement that
would cause a Separately Licensed Component to be conveyed together with the
Work, a licence review should be obtained from qualified counsel.

---

## Component notes

### `sha2` 0.10.9

Cross-process host evidence defines executable, argument, environment,
working-directory, bundle, prompt, process, stdout, and stderr identities as
SHA-256 values. `sha2` is a pure Rust MIT/Apache-2.0 implementation, supports the
workspace MSRV, adds no service or runtime process, and is used only for bounded
in-process hashing. BLAKE3 remains the internal deterministic-ID and
content-addressing primitive elsewhere.

### SurrealDB

Obtained and licensed by the operator independently of the Work. Reached over
the WebSocket/RPC transport implemented in `eliot-store`. Neither vendored nor
redistributed, and not linked. Treated as the present implementation of the
canonical store capability, not as a permanent architectural commitment.

### `wasmtime` 40.0.0

Wasmtime is pinned exactly at 40.0.0, whose declared MSRV is Rust 1.89.0, and
is licensed Apache-2.0 WITH LLVM-exception. The dependency uses only the
component-model, cranelift, runtime, and std features, with default features
disabled; WASI, async, cache, pooling, profiling, and parallel compilation are
not enabled. JIT execution through Cranelift and the Component Model provide
the bounded typed guest ABI required here, with no host imports. This choice
has material binary size and compile-time cost. Any upgrade requires a fresh
MSRV, license, feature, and security review, followed by all full WASM gates.
