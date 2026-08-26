# Package provenance

Дата capture: 2026-08-26. Все raw artifacts находятся в:

`C:\Users\kleym\Downloads\perplexity-portable-computer-audit`

## Provenance chain

```text
HTTPS packages.perplexity.ai repository key
  ↓ gpgv cryptographic verification
signed InRelease / Release
  ↓ SHA-256 + byte size
dists/stable/main/binary-arm64/Packages.gz
  ↓ exact package stanza SHA-256 + byte size
perplexity_26.8.4+build50522_arm64.deb
  ↓ 7-Zip archive listing + extraction
control metadata + rootfs inventory + per-file SHA-256
```

Статус всей цепочки: `CONTENT_CHAIN_VERIFIED`; signer identity: `SIGNATURE_VALID_WITH_UNPINNED_KEY`.

## Repository key

| Поле | Значение |
|---|---|
| URL | `https://packages.perplexity.ai/perplexity.gpg` |
| Size | `1,163` bytes |
| SHA-256 | `71f4be2c585002085e8fe4394c4ee917c08786d1b9ddf5b575be1964993fbe3d` |
| Algorithm | RSA4096 |
| Created | 2026-07-16 |
| Fingerprint | `5CE6FE16BD533152E64EFD93C751F9CAC952A583` |
| UID | `Perplexity AI <support@perplexity.ai>` |

`gpgv` в WSL Ubuntu завершился `0` для обоих вариантов:

- InRelease: good signature, 2026-08-25 09:53:44 EDT;
- Release.gpg + Release: good signature, тот же fingerprint.

Независимый fingerprint pin не найден. Ключ и signed metadata получены с одного origin, поэтому название `VERIFIED` без квалификатора было бы чрезмерным.

## Signed Release identity

| Field | Value |
|---|---|
| Origin / Label | `Perplexity` |
| Suite / Codename | `stable / stable` |
| Components | `main` |
| Architectures | `amd64 arm64` |
| Acquire-By-Hash | `yes` |
| Date | `Tue, 25 Aug 2026 13:53:44 GMT` |
| Valid-Until | absent |

Raw hashes:

| Artifact | Bytes | SHA-256 |
|---|---:|---|
| `InRelease` | 1,727 | `dadd74eabc42f12ffbcb4de1fb0ecf711b1fe6cb79233316b8bdcd91fc1a0161` |
| `Release` | 845 | `9c14c4648e6dd28dbdb8415a805c9fc3366beecb4a0204a8245447f2a9a9bc68` |
| `Release.gpg` | 833 | `5b0f29fb207b4c839b8351c9750c44f902e1df4ab85d0791729750065088803f` |

## Signed index hashes

| Index | Bytes | SHA-256 | Result |
|---|---:|---|---|
| `main/binary-arm64/Packages.gz` | 472 | `214b0dd56e1132300ff5501397122601fe16dca8ac0947212d1a85091a809a42` | exact match |
| uncompressed arm64 `Packages` | 731 | `5b45d4f579ea1c969d5e0793f039feace000ce3ccfb5fda32a273625063ca543` | exact match |
| `main/binary-amd64/Packages.gz` | 472 | `ddc6790b7d5c3c5b7376f179b95b552ad0a932731708fd5fc42ea446548b2be3` | exact match |
| uncompressed amd64 `Packages` | 731 | `aabd1d4f41672bb5d3f4caa80daff9303b8291a7c8158b31a2bfc6ef4d6829b9` | exact match |

Indexes распакованы 7-Zip только после проверки compressed hash/size.

## Selected package stanza

```text
Package: perplexity
Version: 26.8.4
License: unknown
Vendor: Perplexity AI <support@perplexity.ai>
Architecture: arm64
Installed-Size: 584776
Filename: pool/main/p/perplexity/perplexity_26.8.4+build50522_arm64.deb
Size: 161635712
SHA256: 5ac7b5f597e03a888f92a3aaa643138f6cc78a50fd891bc7afabfe86e1e2b994
```

Обратите внимание: Debian `Version` равен `26.8.4`; `build50522` находится в filename и Electron package manifest, а не в поле Debian Version.

## Download result

Literal-plus URL вернул `403 AccessDenied`. RFC-encoded URL `%2B` вернул HTTP 200 без redirect:

`https://packages.perplexity.ai/deb/pool/main/p/perplexity/perplexity_26.8.4%2Bbuild50522_arm64.deb`

Полученный файл:

`C:\Users\kleym\Downloads\perplexity-portable-computer-audit\01-downloads\perplexity_26.8.4+build50522_arm64.deb`

| Check | Expected | Observed | Result |
|---|---:|---:|---|
| Size | 161,635,712 | 161,635,712 | `PASS` |
| SHA-256 | `5ac7…b994` | `5ac7…b994` | `PASS` |

`.deb` не имеет отдельной embedded package signature; доверие строится через signed repository metadata.

## Archive identity

Outer `.deb` members по `7z l -slt`:

| Member | Bytes |
|---|---:|
| `debian-binary` | 4 |
| `control.tar.xz` | 76,948 |
| `data.tar.xz` | 161,558,572 |

Uncompressed tar sizes:

- `control.tar`: 225,280 bytes;
- `data.tar`: 600,463,360 bytes.

Path-safety review:

- control: 5 tar members;
- data: 2,117 tar member paths;
- no absolute/traversal paths;
- no non-empty symbolic/hard links;
- no device/socket/FIFO members;
- resolved extracted paths remained under selected output roots.

Windows extraction fidelity limitation: owner/group, exact Unix mode and some tar metadata могут не сохраниться на NTFS; raw `*-listing-slt.txt` files являются evidence для исходной семантики.

## Rootfs manifest

Generated under `99-generated-reports`:

- `file-inventory.csv`;
- `file-inventory.json`;
- `all-hashes.sha256`;
- `directory-tree.txt`;
- `largest-files.txt`;
- `archive-listings.txt`;
- component-oriented lists for executables, scripts, configs, services, licenses, source-like and binary-like files.

Rootfs totals:

- files: `2,080`;
- bytes: `598,811,297`.

## Source-package status

Signed `Release` не перечисляет `main/source/Sources`, а package stanza не содержит `Source`. Поэтому:

`NO_PUBLIC_APT_SOURCE_INDEX_DISCOVERED`

Это утверждение ограничено официальным APT snapshot и не является доказательством, что исходники нигде не существуют.

