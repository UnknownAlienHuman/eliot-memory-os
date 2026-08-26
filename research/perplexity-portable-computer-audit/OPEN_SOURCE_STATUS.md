# Component-level open-source status

Audit date: 2026-08-26.

## Classification rules

- `OPEN_SOURCE_CONFIRMED`: exact component/version source and an open-source license are both attributable;
- `OPEN_WEIGHTS_CONFIRMED`: model weights are public under an attributable open-weight/open license; not necessarily OSI software;
- `SOURCE_AVAILABLE_LICENSE_UNKNOWN`: readable implementation artifact exists, but no applicable license grant was found;
- `BINARY_ONLY_NO_PUBLIC_SOURCE_FOUND`: only binary evidence was found after official/source/mirror checks;
- `THIRD_PARTY_OPEN_SOURCE`: packaged third-party software with attributable upstream/license;
- `UNKNOWN`: identity or license boundary cannot be resolved.

## Findings

| Component | Package evidence | Public source/license evidence | Classification |
|---|---|---|---|
| Debian package as a whole | stanza says `License: unknown`; no `Source` field/index | no exact public source package/repo found | `BINARY_ONLY_NO_PUBLIC_SOURCE_FOUND` |
| Electron/Chromium runtime | Electron executable plus `LICENSE.electron.txt`, `LICENSES.chromium.html` | known upstream projects and bundled notices | `THIRD_PARTY_OPEN_SOURCE` |
| `perplexity-rpc-server` | 169 MB AArch64 Rust ELF, exact SHA, internal source paths | exact GitHub/path/hash searches empty; no source offer | `BINARY_ONLY_NO_PUBLIC_SOURCE_FOUND` |
| local harness/orchestrator | Rust symbols/paths and embedded prompts | no exact public source found | `BINARY_ONLY_NO_PUBLIC_SOURCE_FOUND` |
| sandbox/PII/automation/state modules | Rust symbols, SQL and policy strings | no exact public source found | `BINARY_ONLY_NO_PUBLIC_SOURCE_FOUND` |
| `pplx-search` | AArch64 Rust broker client | no exact public source found | `BINARY_ONLY_NO_PUBLIC_SOURCE_FOUND` |
| `libaic.so` | stripped AArch64 shared library | no exact public source/license found | `BINARY_ONLY_NO_PUBLIC_SOURCE_FOUND` |
| Electron ASAR application JS | 1,136 extracted files, readable bundled JS | no core license grant attributable to Perplexity application code | `SOURCE_AVAILABLE_LICENSE_UNKNOWN` |
| bundled local-template/skills | readable Markdown/TOML/Python/JSON | no applicable bundle/core license found | `SOURCE_AVAILABLE_LICENSE_UNKNOWN` |
| `uv` | bundled Rust binary | upstream Astral `uv` is open-source; exact binary/source reproducibility not proven here | `THIRD_PARTY_OPEN_SOURCE`, exact build mapping unverified |
| bundled Node dependencies | many license files inside ASAR | per-dependency licenses available | `THIRD_PARTY_OPEN_SOURCE` |
| Qwen3.8-27B base | model is not embedded in `.deb` | official public repo, Apache-2.0 | `OPEN_WEIGHTS_CONFIRMED` / base only |
| PPLX 27B / Perplexity Qwen checkpoint | catalog identifiers; no weights in `.deb` | public card has `License: other`, auth/private-flow language; exact 20260824 repo unresolved | `WEIGHTS_OR_METADATA_AVAILABLE_LICENSE_UNKNOWN_OR_RESTRICTED` |
| Nemotron 3.5 Lightning | future catalog/announcement; absent from `.deb` | NVIDIA public OpenMDW-1.1 model repo | `OPEN_WEIGHTS_CONFIRMED`, future optional component |
| vLLM/llama.cpp engines | provider/catalog support; no complete engine payload in `.deb` | upstream projects are open-source | `THIRD_PARTY_OPEN_SOURCE`; Perplexity patches/build correspondence unknown |

## Packaged license material

Rootfs contains:

- `/opt/Perplexity/LICENSE.electron.txt`;
- `/opt/Perplexity/LICENSES.chromium.html`;
- licenses inside ASAR `node_modules`.

No discovered top-level Perplexity core license, source offer, SBOM, CycloneDX/SPDX manifest or written correspondence between the core binaries and a public source revision.

The presence of third-party notices does not license Perplexity-owned code.

## Public Perplexity repositories are not provenance matches

Official GitHub projects such as `pplx-garden`, `pplx-kernels`, `pplx-rs`, `numbat` and `electron-sdk` are adjacent technology, not matching source for:

- `pplx/rust/libs/localharness/...`;
- `perplexity-rpc-server`;
- `pplx-search`;
- `libaic.so`;
- build `50522`.

No component was marked open merely because its vendor has other open repositories.

## Model nuance

The official Perplexity research article calls Qwen 3.8 an open-source model. That accurately supports the base Qwen component. It does **not** establish that:

- PPLX post-training data/code is open;
- the Perplexity checkpoint uses the base Apache-2.0 grant without additional terms;
- the packaged harness is open-source;
- private optimized artifacts or Docker layers are redistributable.

For the Perplexity checkpoint, the public model-card label `other` is controlling until exact license files/terms are obtained.

## Conclusion

Portable Computer is not supportably classifiable as an open-source application. It is a proprietary/unknown-license core distributed with substantial third-party open-source software and optional open/open-weight base models.

The honest aggregate status is:

`PROPRIETARY_OR_LICENSE_UNKNOWN_CORE + THIRD_PARTY_OPEN_SOURCE_RUNTIME + MIXED_MODEL_LICENSES`

## Evidence needed to promote a component

A `BINARY_ONLY` or `UNKNOWN` row can be promoted only with:

1. exact source repository and revision;
2. exact component/version/build mapping;
3. applicable license text;
4. reproducible or vendor-attested binary correspondence;
5. complete notices/SBOM for distributed dependencies.

