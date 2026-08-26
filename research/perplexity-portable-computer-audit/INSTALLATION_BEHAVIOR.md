# Installation and runtime bootstrap behavior

## Package dependencies

Debian package depends on desktop/runtime libraries plus explicit isolation/runtime surfaces:

`libgtk-3-0`, `libnotify4`, `libnss3`, `libxss1`, `libxtst6`, `xdg-utils`, `libatspi2.0-0`, `libuuid1`, `libsecret-1-0`, `bubblewrap`, `libdbus-1-3`, `libvulkan1`, `libasound2`; recommends `libappindicator3-1`.

The package was **not installed**. The following is a static reading of `control`, `postinst` and `postrm`.

## Maintainer scripts present

| Script/metadata | Present | Executed in audit |
|---|---:|---:|
| `control` | yes | no, text-read only |
| `md5sums` | yes | no, text-read only |
| `postinst` | yes | no |
| `postrm` | yes | no |
| `preinst` | no | n/a |
| `prerm` | no | n/a |
| `config` / triggers | no | n/a |

## `postinst` mutations

### 1. Command registration

Creates the `perplexity` alternative:

```text
/usr/bin/perplexity
  → /etc/alternatives/perplexity
  → /opt/Perplexity/perplexity
```

If `update-alternatives` is unavailable, creates a direct symlink.

### 2. Chromium sandbox mode

Runs a small host capability test:

```text
unshare --user true
```

- if user namespaces are unavailable, sets `/opt/Perplexity/chrome-sandbox` to mode `4755`;
- otherwise sets it to `0755`.

This is a maintainer-script host probe, not execution of the Perplexity binary. The audit did not run it.

### 3. Desktop databases

If available, calls:

- `update-mime-database /usr/share/mime`;
- `update-desktop-database /usr/share/applications`.

### 4. AppArmor profile

If AppArmor is enabled and `apparmor_parser` accepts ABI 4 syntax:

- copies `/opt/Perplexity/resources/apparmor-profile` to `/etc/apparmor.d/perplexity`;
- loads/replaces it outside chroot.

The profile grants `userns` to Electron and defines `perplexity-bwrap`, but both profiles use `flags=(unconfined)`. It is an enabling profile for Ubuntu user namespaces, not the substantive tool policy. The actual tool boundary is implemented by the Rust sandbox/Bubblewrap layer.

## `postrm` behavior

- removes the `perplexity` alternative/direct symlink;
- unloads and deletes `/etc/apparmor.d/perplexity` when present.

No cleanup code was found for:

- `~/.pplx`;
- downloaded models;
- Docker images/containers;
- local SQLite databases, trajectories, histories or caches;
- application user-data directory.

Therefore package uninstall is only `PARTIALLY_REVERSIBLE`; post-launch payload cleanup remains unknown/manual.

## Explicitly absent from maintainer scripts

No static evidence of:

- `curl`, `wget`, Hugging Face or model download;
- Docker/container pull or start;
- systemd service/timer/socket registration;
- user/group creation;
- daemon start;
- Perplexity application/Rust binary execution;
- credential prompt.

## Desktop launch

`/usr/share/applications/perplexity.desktop` launches:

```text
/opt/Perplexity/perplexity %U
```

No background OS service is packaged. Long-running work and automations are app-owned and require the application/local mode to be active according to the bundled automation skill.

## Post-launch bootstrap surfaces

The `.deb` contains a functional desktop control plane but omits several large runtime payloads.

### Python environment

`local-template/manifest.json` points to a pinned `requirements.txt`. The package contains `uv` but no provisioned venv/wheels. Static template/provisioner evidence indicates first enable provisions `~/.pplx` and installs hash-pinned Python dependencies with `uv --require-hashes`.

Status: `RUNTIME_NETWORK_BOOTSTRAP_CONFIRMED_STATIC`; exact package index URLs and downloaded byte total remain unknown.

### Model and inference engines

Rust strings/catalogs describe:

- llama.cpp discovery/provisioning;
- vLLM Docker provider;
- a pinned `vllm/vllm-openai@sha256:ffb2d59b...` image identifier;
- Perplexity model repositories on Hugging Face;
- supervised container labels and stale-container removal;
- private binary/model flows requiring `HF_TOKEN` in some branches.

No model weights, Docker image layers or image archive were found in the `.deb`.

Status: `PACKAGE_IS_RUNTIME_BOOTSTRAPPER_FOR_MODELS_AND_ENGINES`.

### Host setup elevation

Electron main contains a narrow host-setup channel:

- renderer triggers setup but does not supply the command;
- Rust sidecar supplies the command plan;
- only `pkexec` and `sudo` runners are allowed;
- comments scope the current privileged precondition path to the containerized DGX Spark engine.

This is a useful anti-confused-deputy boundary, but dynamic privilege prompts/commands were not executed.

## Package role conclusion

| Candidate classification | Result |
|---|---|
| Pure downloader/bootstrap stub | false |
| Fully self-contained local AI stack | false |
| Desktop/control plane + harness + runtime bootstrapper | **true** |

The package can present UI, orchestration, durable state, sandbox policy, skills and engine management, but cannot perform advertised local inference without external model/engine provisioning.

## Rollback and disk-risk notes

Before any future runtime experiment:

1. record free space and Docker/Hugging Face state;
2. bind a disposable `PPLX_DATA_DIR` only if packaged build actually permits it—current packaged JS scrubs this dev override, so do not assume it works;
3. capture model/image identifiers and byte sizes before authorization;
4. record package, AppArmor, alternatives and user-data state;
5. define cleanup for containers/images/models/venv/SQLite separately from `apt remove`.

No runtime installation is required for this static audit and none was performed.

