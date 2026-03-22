# Changelog

All notable changes to `pt` (process_triage) are documented in this file.

Versions marked **[GitHub Release]** have published release artifacts on GitHub.
Plain tags without that label are git-only tags with no corresponding release page.

Repository: <https://github.com/Dicklesworthstone/process_triage>

---

## [Unreleased] (after v2.0.5)

66 commits since v2.0.5 as of 2026-03-21. Major theme: **provenance-aware blast-radius estimation**.

### Provenance Engine (epic bd-ppcl)

- Full provenance subsystem: lineage collectors, resource collectors, workspace evidence, shared-resource provenance graph, blast-radius scoring, and continuity tracking across scans ([efa8520](https://github.com/Dicklesworthstone/process_triage/commit/efa8520d389297b25f29c35c7fdd83c850f355ad), [bdacc39](https://github.com/Dicklesworthstone/process_triage/commit/bdacc39dddd24b37bd4105c291418bf85652f8c2), [eb64cf2](https://github.com/Dicklesworthstone/process_triage/commit/eb64cf2f3f9d9d600252a82924942e4e60c5af64), [d9f7cf6](https://github.com/Dicklesworthstone/process_triage/commit/d9f7cf68cbb1a8c91e4b3ced47b3902c049c98f0))
- Unified blast-radius estimator with direct-impact heuristics and indirect-impact uncertainty propagation ([7b4b297](https://github.com/Dicklesworthstone/process_triage/commit/7b4b29771a57c639df7c37ef8035ab55c0966848), [dfb04c5](https://github.com/Dicklesworthstone/process_triage/commit/dfb04c5b1f0320833d3851da5b9396c3ea6d1a19))
- Provenance explanation with counterfactual stories (`pt provenance explain`) ([63b55f5](https://github.com/Dicklesworthstone/process_triage/commit/63b55f54c6ba9071106033ec00c0dc7e24e7703b))
- TUI provenance inspector with daemon alerts and fleet integration ([6d396e8](https://github.com/Dicklesworthstone/process_triage/commit/6d396e8210f86368b8415d6803da57f775fbe508), [4b3761a](https://github.com/Dicklesworthstone/process_triage/commit/4b3761a467b0b39938491c0eb4e17e87a2141b9c))
- Structured output contract, narrative expansion, policy gates, and decision memory for provenance ([b3f3172](https://github.com/Dicklesworthstone/process_triage/commit/b3f31725d751f44902680d7ba636a8eaf9e97597))

### Inference & Math

- Queueing-theoretic stall detection with load-dependent service rates and M/M/1 tail probability ([0744776](https://github.com/Dicklesworthstone/process_triage/commit/0744776f10bf654a85310dd3df73deb3d56ad56a), [40ec904](https://github.com/Dicklesworthstone/process_triage/commit/40ec90411c082bce378a127faef2d5ad8ee1e559))
- Mondrian conformal risk control for robot mode ([3f1c17c](https://github.com/Dicklesworthstone/process_triage/commit/3f1c17cca5c95f2c6e86fecaca331c0f170e710d))
- Major posterior refinement and provenance type expansion in pt-common (+692 lines) ([4e9588f](https://github.com/Dicklesworthstone/process_triage/commit/4e9588f845fdc122ff8c307932d5a49f8482475c))
- Precomputed tables, stable distribution, and expanded posterior math in pt-math (+225 lines) ([9b9a9df](https://github.com/Dicklesworthstone/process_triage/commit/9b9a9df1c2e7fe196007776500546c8752c2465c))

### CLI & Session

- Evidence export and provenance query subcommands ([cd5ac6a](https://github.com/Dicklesworthstone/process_triage/commit/cd5ac6a948ec993a383e0d4d519d40e4982ce08b), [6bcd2d1](https://github.com/Dicklesworthstone/process_triage/commit/6bcd2d11250b7c476a61273e9a4665723ffa9276))
- Session diff engine with comprehensive diff tests (+382 lines) ([03385f4](https://github.com/Dicklesworthstone/process_triage/commit/03385f40dee2a9e7e8bf7938d5008e6365e6fa6e))
- Major CLI expansion and inference engine improvements (+632 lines) ([779c879](https://github.com/Dicklesworthstone/process_triage/commit/779c8794f09590112140fe71929ea98f045081f4))

### Telemetry & Internals

- Wait-free prober, disruptor/recorder, and provenance privacy model ([ee5e773](https://github.com/Dicklesworthstone/process_triage/commit/ee5e773cda7ee47970fb28a62daa2c0be365f3c4))
- Provenance testing harness with fixtures and documentation ([a6ef08f](https://github.com/Dicklesworthstone/process_triage/commit/a6ef08fc53236d5a6c9413f7aa3dfdf5557967e0))
- Network resource collector module ([148f3a9](https://github.com/Dicklesworthstone/process_triage/commit/148f3a91395cb135f1799ac6a03f1f0e02ebcf99))
- Snapshot persistence with provenance integration (+183 lines) ([87a28aa](https://github.com/Dicklesworthstone/process_triage/commit/87a28aaed10bada6805f1fe56abcff8ffd7e446c))

### Testing

- Alien technology integration tests ([151cc6e](https://github.com/Dicklesworthstone/process_triage/commit/151cc6ec78e64cc05ca103a64f457d08672a3538))
- Blast-radius provenance regression suite ([8756a28](https://github.com/Dicklesworthstone/process_triage/commit/8756a2890b93b9d80dd63e9ea295905b9885f957))
- Resource-conflict provenance regression tests ([07f422f](https://github.com/Dicklesworthstone/process_triage/commit/07f422f901004aa005b1e15d9f208574e269a83d))
- E2E session diff tests (+172 lines) ([9c1bc1d](https://github.com/Dicklesworthstone/process_triage/commit/9c1bc1d7ad30ae92131a4e0ea62384b5c82086a5))
- Expanded bundle, evidence, and provenance tests (+620 lines) ([fff6773](https://github.com/Dicklesworthstone/process_triage/commit/fff6773803505ab889261bb9c159099bf07f383c))

---

## [v2.0.5] -- 2026-03-14 **[GitHub Release]**

Tagged at [`772447b`](https://github.com/Dicklesworthstone/process_triage/commit/772447bdd1beef8100d60ebadd646a7637f5b14d). Published to GitHub Releases on 2026-03-14.

21 commits since v2.0.4. Theme: **pt-math extraction, macOS hardening, code quality sweep**.

### New Crate: pt-math

- Add normal distribution, expand beta/gamma functions ([48bc89b](https://github.com/Dicklesworthstone/process_triage/commit/48bc89b12a937fa75691ffa7bded5f07dfe3af2f))
- Migrate statistical functions out of pt-core into pt-math, harden mem-pressure scoring ([441848f](https://github.com/Dicklesworthstone/process_triage/commit/441848fc886540c7bddd1a17d3dabec294e6d122))

### Features

- Wrapper-aware help in `pt` shell script ([9083eeb](https://github.com/Dicklesworthstone/process_triage/commit/9083eeb))
- `pt_plan` MCP tool and just-in-time identity revalidation ([921ada4](https://github.com/Dicklesworthstone/process_triage/commit/921ada4))
- `pt scan deep` alias routing to deep-scan subcommand ([a751c7c](https://github.com/Dicklesworthstone/process_triage/commit/a751c7c))
- Deep-scan and report commands, deduplicate math into pt-math ([efa2e27](https://github.com/Dicklesworthstone/process_triage/commit/efa2e27))
- Evidence glyph mapping for all feature types ([c13ab17](https://github.com/Dicklesworthstone/process_triage/commit/c13ab17df0ea083e1a28fda5757e532e3f7699d2))
- Contextual bandits, drift detection, and session typestate system ([70352e2](https://github.com/Dicklesworthstone/process_triage/commit/70352e22b2ae3fe51c4252d6365e6c95e093896a))
- Query sessions subcommand with multi-format output ([6c20953](https://github.com/Dicklesworthstone/process_triage/commit/6c20953c6e58ede2ad4289856560224d6b912311))

### Fixes

- Allocation-free critical-file detection, MCP tool fixes, pattern learning and beta math corrections ([e3c67d5](https://github.com/Dicklesworthstone/process_triage/commit/e3c67d5e3b39f0cd6fca66630fb64982b14a7055))
- Eliminate TOCTOU races and harden file-size limits across crates ([6977d1f](https://github.com/Dicklesworthstone/process_triage/commit/6977d1f))
- Harden release trust pinning and update path safety ([ded106a](https://github.com/Dicklesworthstone/process_triage/commit/ded106ac6f0e133ddfb8af0be871ccdca5fc5643))
- Serialize both CpuEvidence variants in evidence JSON ([0ea4070](https://github.com/Dicklesworthstone/process_triage/commit/0ea40707941827e759a63f08b1b7a3dea87e32c6))
- Resolve all clippy warnings and add category prior defaults ([89693cb](https://github.com/Dicklesworthstone/process_triage/commit/89693cb1a3382620ef6c285021ce3c2b3ad62a19))
- Use actual visible height for TUI page scrolling ([2eafeaf](https://github.com/Dicklesworthstone/process_triage/commit/2eafeaf))

### Refactoring

- `ProcessNotFound` status, extend prechecks to macOS, harden signal/recovery logic ([3d2bb4b](https://github.com/Dicklesworthstone/process_triage/commit/3d2bb4bd18bf730c2ec7fb216ac808165f86fc68))
- Unify proc parsing, expand macOS collection, simplify deep_scan/ancestry ([81b7e6a](https://github.com/Dicklesworthstone/process_triage/commit/81b7e6ae9f7c1cc467c7208f107667b5df957e22))
- Streamline supervision and session subsystems ([72165f8](https://github.com/Dicklesworthstone/process_triage/commit/72165f857b3a70991958382a7494787f0069226f))
- Deduplicate ps-line parsing, fix zero-parallel panic, harden JSONL serialization ([cd9fd6c](https://github.com/Dicklesworthstone/process_triage/commit/cd9fd6c4941177bffddac8401dedbc0e66257049))
- Eliminate redundant sorts in quantile functions, replace unwrap with safe patterns ([ac03456](https://github.com/Dicklesworthstone/process_triage/commit/ac034566781dfb1a42db1e7994bdd089d07c4b12))
- Use `launchctl bootout` for launchd, fix `flip_conditions` log-odds math ([a48e8cf](https://github.com/Dicklesworthstone/process_triage/commit/a48e8cf808745b15b6517a786b3bcfd7438ed314))
- Rustfmt pass, macOS environ support, type-safe signature categories ([87ebd15](https://github.com/Dicklesworthstone/process_triage/commit/87ebd1571fee34e4717bab971581039e79cbaa44))
- Replace unwrap with expect, use iterator in HSMM, promote regex to static LazyLock ([2b9d48b](https://github.com/Dicklesworthstone/process_triage/commit/2b9d48b41d49df85f0f8f8ab872b34882f6e08fd))

### Testing

- E2E tests for outcome markers and zero-parallel SSH scan ([4493346](https://github.com/Dicklesworthstone/process_triage/commit/44933468fa86150d864e868775d0b4c8636745ef))
- Update recovery_tree bench and recovery_properties tests for typed ActionStatus ([72e4a6e](https://github.com/Dicklesworthstone/process_triage/commit/72e4a6e89a3f17d306602f73be51db884e3052de))
- Update wrapper, command, and integration test expectations ([2d8f419](https://github.com/Dicklesworthstone/process_triage/commit/2d8f419d0c27c687f35c2f91bd93a713580b9a5b))

---

## [v2.0.4] -- 2026-03-09 **[GitHub Release]**

Tagged at [`9444120`](https://github.com/Dicklesworthstone/process_triage/commit/9444120bd5390de6f5539d56bf522ca3ffb0caf1). Published to GitHub Releases on 2026-03-09. First release with six-platform binary matrix (Linux x86_64/aarch64 glibc+musl, macOS x86_64/aarch64) and ECDSA-signed artifacts.

100+ commits since v2.0.3 (spanning 2026-02-13 through 2026-03-08). This is the largest release by commit count.

### TUI Overhaul (ftui migration)

- Full migration from ratatui to ftui framework: model, key dispatch, widget ports, dual rendering paths, `--inline` mode ([1cd02bf](https://github.com/Dicklesworthstone/process_triage/commit/1cd02bfbce1e26d0faca5bcefe41e9b3e7eea4fc), [1e23c72](https://github.com/Dicklesworthstone/process_triage/commit/1e23c72ca1a383c6ae542cfad98adbcb6514a3cb), [ba3c83c](https://github.com/Dicklesworthstone/process_triage/commit/ba3c83ce83811c051d93e40ad869bffe069a33fc), [ee26706](https://github.com/Dicklesworthstone/process_triage/commit/ee26706))
- TUI accessibility: `--accessible`, `--reduce-motion`, `--theme`, `--high-contrast` flags, command palette, screen reader announcements ([427cc49](https://github.com/Dicklesworthstone/process_triage/commit/427cc49), [eb94773](https://github.com/Dicklesworthstone/process_triage/commit/eb94773), [e05d274](https://github.com/Dicklesworthstone/process_triage/commit/e05d274), [92bac98](https://github.com/Dicklesworthstone/process_triage/commit/92bac985c07b44d95bf3a462faaf6fcf1c01a65d))
- AuxPanel widget for wide-breakpoint action preview ([3484bba](https://github.com/Dicklesworthstone/process_triage/commit/3484bba))
- Toast notifications for async operation feedback ([179fa7c](https://github.com/Dicklesworthstone/process_triage/commit/179fa7c9ac7ae0e537a0abec50a9f5eba76dcda0))

### Inference & Decision Theory

- Contextual bandits and drift detection ([70352e2](https://github.com/Dicklesworthstone/process_triage/commit/70352e22b2ae3fe51c4252d6365e6c95e093896a))
- Inference ledger with structured evidence tracking and confidence scoring ([738f8c2](https://github.com/Dicklesworthstone/process_triage/commit/738f8c2982ade3b06a05337c0c5d4f9c3d49015b))
- Evidence glyph mapping for all feature types ([c13ab17](https://github.com/Dicklesworthstone/process_triage/commit/c13ab17df0ea083e1a28fda5757e532e3f7699d2))

### Installer & Release Infrastructure

- ECDSA P-256 signature verification wired into update flow ([6d8fc48](https://github.com/Dicklesworthstone/process_triage/commit/6d8fc480bb45292eaf7d51a894cf4e191e73271c))
- Rollback safety, CI release workflow, and comprehensive installer test coverage ([075236d](https://github.com/Dicklesworthstone/process_triage/commit/075236d5f94c0cdb1b45de6540263d6e1d868571))
- Make release signing optional when secret is absent ([9444120](https://github.com/Dicklesworthstone/process_triage/commit/9444120bd5390de6f5539d56bf522ca3ffb0caf1))
- Update macOS CI runners (from deprecated macos-13) ([b51e016](https://github.com/Dicklesworthstone/process_triage/commit/b51e016d2daaaa07d77ea3e09adb76591a337246))
- Accept static-pie binaries in musl linking check ([b7352a4](https://github.com/Dicklesworthstone/process_triage/commit/b7352a40507e42cb87c70c162767a6c638a989ba))

### Security Hardening

- Cap KDF iterations, fix rate limiter TOCTOU race, prevent blast-radius overflow ([b5884eb](https://github.com/Dicklesworthstone/process_triage/commit/b5884eb1bd1d3860a7903b9bfc3d9a00f941362a))
- Fix safety, correctness, and security issues across 15 source files ([7e05f7d](https://github.com/Dicklesworthstone/process_triage/commit/7e05f7d918220e18d13ee2da0f4f51ad046e02e5))
- Harden release trust pinning and update path safety ([ded106a](https://github.com/Dicklesworthstone/process_triage/commit/ded106ac6f0e133ddfb8af0be871ccdca5fc5643))

### Correctness Fixes

- Fix 14 correctness and safety issues across inference, collection, redaction, and telemetry ([34c7f90](https://github.com/Dicklesworthstone/process_triage/commit/34c7f9046aaef70182a388475dc8da211c66f965))
- TTY/shell activity detection, conformal predictor self-call, HSMM duration tracking, LFP credal set allocation ([f29bf81](https://github.com/Dicklesworthstone/process_triage/commit/f29bf81a9c7b06966f588039c4549189409f36c3))
- Prevent panic on truncated `/proc/PID/stat` content in ancestry parser ([630e4a8](https://github.com/Dicklesworthstone/process_triage/commit/630e4a88c63ffa5d5d65070a58bdc8bfdadb2265))
- Durable `sync_all` for alpha investing state persistence, fix CVaR VaR tracking ([a7e3aa3](https://github.com/Dicklesworthstone/process_triage/commit/a7e3aa3a69b883a1eb6efbc4e2ab5243dcb3adf2))
- Correct policy pattern matching, guard against NaN loss, tolerate plugin BrokenPipe ([2021ad6](https://github.com/Dicklesworthstone/process_triage/commit/2021ad694e279e1ec32acf38c3ad033cefbd2db6))
- Relax resident-pages assertion for freshly spawned processes ([a6b6e90](https://github.com/Dicklesworthstone/process_triage/commit/a6b6e9026046d4986ee03bfd9fd98f6b2f1e926b))
- Correct off-by-one in `quick_scan.rs` minimum field check ([7ea1a1f](https://github.com/Dicklesworthstone/process_triage/commit/7ea1a1fc56e92d36119934e96b15a0be58d1291e))
- Lower macOS field-count threshold to match `macos.rs` ([91b669e](https://github.com/Dicklesworthstone/process_triage/commit/91b669e07f7641a96fe3d8cdf70a4829c9e9e31c))

### Plugin & Packaging

- Plugin system for custom evidence sources and action hooks ([4f1bddf](https://github.com/Dicklesworthstone/process_triage/commit/4f1bddf270f8ed8a5d215b83e2620b2070e7d253))
- Shell completions, Dockerfile, and justfile ([e371dd5](https://github.com/Dicklesworthstone/process_triage/commit/e371dd53712354c279b762bc4babd65123b3df21))
- Query sessions subcommand with multi-format output ([6c20953](https://github.com/Dicklesworthstone/process_triage/commit/6c20953c6e58ede2ad4289856560224d6b912311))

### Testing & Benchmarks

- Criterion benchmarks for Wonham filter, Gittins index, escalation, fleet-registry, fleet-pattern, fleet-FDR, VOI, SPRT/GLR, CVaR, submodular selection, goal-plan, mem-pressure, rate-limit, respawn-loop, sequential stopping, robot constraints, time-bound, DRO, dependency-loss, daemon triggers, myopic policy ([1d26de0](https://github.com/Dicklesworthstone/process_triage/commit/1d26de0), [7118dd8](https://github.com/Dicklesworthstone/process_triage/commit/7118dd8), [af71251](https://github.com/Dicklesworthstone/process_triage/commit/af71251), [0fe2d89](https://github.com/Dicklesworthstone/process_triage/commit/0fe2d89), [8898e65](https://github.com/Dicklesworthstone/process_triage/commit/8898e65), [fa1ab42](https://github.com/Dicklesworthstone/process_triage/commit/fa1ab42))
- Property-based tests (proptest) for FDR, alpha-investing, CVaR, SPRT/GLR, VOI, myopic policy, HSMM, robust inference, compound Poisson, escalation, goal-plan, goal-progress, mem-pressure, rate-limit, respawn-loop, time-bound, DRO, dependency-loss, sequential stopping, robot constraints, causal/load-aware/martingale invariants ([e03d81a](https://github.com/Dicklesworthstone/process_triage/commit/e03d81a), [f3f3243](https://github.com/Dicklesworthstone/process_triage/commit/f3f3243), [7389607](https://github.com/Dicklesworthstone/process_triage/commit/7389607), [76944f6](https://github.com/Dicklesworthstone/process_triage/commit/76944f6), [59042e4](https://github.com/Dicklesworthstone/process_triage/commit/59042e4))
- Daemon chaos coverage: SIGTERM, SIGHUP, SIGKILL restart, signal-storm resilience ([4326cb0](https://github.com/Dicklesworthstone/process_triage/commit/4326cb0), [5ea655a](https://github.com/Dicklesworthstone/process_triage/commit/5ea655a), [4694216](https://github.com/Dicklesworthstone/process_triage/commit/4694216), [012b873](https://github.com/Dicklesworthstone/process_triage/commit/012b873))
- Replay/simulation mode with snapshot recording and built-in scenarios ([5f46722](https://github.com/Dicklesworthstone/process_triage/commit/5f46722))

---

## [v2.0.3] -- 2026-02-13

Tagged at [`abe30a2`](https://github.com/Dicklesworthstone/process_triage/commit/abe30a22a5426b468f3f4f3d94962549dcad7d9e). Git tag only (no GitHub Release page). Release-engineering fix to unblock cross-target builds.

### Changes

- Fix cross-target builds for the release workflow ([abe30a2](https://github.com/Dicklesworthstone/process_triage/commit/abe30a22a5426b468f3f4f3d94962549dcad7d9e))
- TUI Toast notifications for async operation feedback ([179fa7c](https://github.com/Dicklesworthstone/process_triage/commit/179fa7c9ac7ae0e537a0abec50a9f5eba76dcda0))

---

## [v2.0.2] -- 2026-02-13

Tagged at [`fa2a64a`](https://github.com/Dicklesworthstone/process_triage/commit/fa2a64a564b93da308277409851e19877db5a20f). Git tag only. Bumped version for a release workflow retry.

### Changes

- Isolate cargo target dir in release workflow to fix parallel build conflicts ([addc1fc](https://github.com/Dicklesworthstone/process_triage/commit/addc1fc71f5a1fab8e40e751739276abfbbb850f))
- Version bump to 2.0.2 ([fa2a64a](https://github.com/Dicklesworthstone/process_triage/commit/fa2a64a564b93da308277409851e19877db5a20f))

---

## [v2.0.1] -- 2026-02-13

Tagged at [`956edd7`](https://github.com/Dicklesworthstone/process_triage/commit/956edd7a860c0e6376e3a752153d1494f84c4f3b). Git tag only. CI verification pass.

### Changes

- Update Cargo.lock dependencies and sync beads issue tracker ([2db881b](https://github.com/Dicklesworthstone/process_triage/commit/2db881bc4ef3a567e591c71b3aae8af43a40e9c5))
- Close CI verification bead after all checks pass ([956edd7](https://github.com/Dicklesworthstone/process_triage/commit/956edd7a860c0e6376e3a752153d1494f84c4f3b))

---

## [v2.0.0] -- 2026-02-13

Tagged at [`f327f51`](https://github.com/Dicklesworthstone/process_triage/commit/f327f51781a5a6cf1bb84b9e765ac8f3ff1c15c1). Git tag only. This is the foundational release -- a from-scratch rewrite of the original bash script into a Rust workspace with 827 commits between the v2.0.0 shell-script prototype and the tagged release.

### Architecture

Complete rewrite from a single bash script into a multi-crate Rust workspace:
- **pt-core** -- CLI binary, inference engine, process collection, action executor, TUI, daemon, fleet mode
- **pt-common** -- Shared types: process identity, evidence structures, capabilities, categorization
- **pt-math** -- Numerically stable math: Beta/Gamma distributions, Dirichlet-Multinomial posterior, log-domain normalization, hazard rates
- **pt-config** -- Configuration loading and schema validation
- **pt-telemetry** -- Batched Parquet writer with crash safety, shadow mode observation storage
- **pt-bundle** -- Session bundle serialization for agent/fleet exchange
- **pt-redact** -- PII redaction for safe session sharing
- **pt-report** -- HTML/markdown report generation

### Bayesian Inference Engine

- 40+ statistical models with conjugate posteriors for process classification ([e274f1a](https://github.com/Dicklesworthstone/process_triage/commit/e274f1a78af884bc716668166395770b86d803ba))
- Conformal prediction module with distribution-free coverage guarantees ([64ce642](https://github.com/Dicklesworthstone/process_triage/commit/64ce642eda68ef31969d3242c30613bc6648b71d))
- Evidence ledger for full classification explainability ([5c192ce](https://github.com/Dicklesworthstone/process_triage/commit/5c192ce9589b76eea49b658a0e46c3aad6a50902))
- CTW prequential predictor for sequence anomaly detection ([740e5c3](https://github.com/Dicklesworthstone/process_triage/commit/740e5c3a183a03a298a01bbfc4f66a2f89aa5dad))
- Bayes factor computation, alpha-investing for multiple testing ([3adf6b0](https://github.com/Dicklesworthstone/process_triage/commit/3adf6b083f2c8d3fb43fd511b2a583adb8246648))
- What-if flip-conditions explainer ([ba24374](https://github.com/Dicklesworthstone/process_triage/commit/ba243749fde0ea9e588a4f9f113908cffc59ebe9))
- Confidence visualization with safety/gate badges ([3b0655b](https://github.com/Dicklesworthstone/process_triage/commit/3b0655bd21ea0e72406b2ead4a40100885c756f6))

### Process Collection

- Deep scan with full `/proc` introspection: sched info, environ, open FDs, cgroup, network connections ([04f2ac0](https://github.com/Dicklesworthstone/process_triage/commit/04f2ac098eb8c3382a42323f6e9fee3378ff93e3), [74099ff](https://github.com/Dicklesworthstone/process_triage/commit/74099ff0146b2684279bc4d8ed52e4620b4fa116))
- CPU tick-delta features (k_ticks/n_ticks/u/u_cores) ([7d9c4fb](https://github.com/Dicklesworthstone/process_triage/commit/7d9c4fb2ae2aec2cffd07077eb888ca5d6ff22e4))
- GPU process detection for CUDA and ROCm ([e78bf71](https://github.com/Dicklesworthstone/process_triage/commit/e78bf71d2a6d0973732c7e13a95b40211133530a))
- Incremental scanning engine ([aa57785](https://github.com/Dicklesworthstone/process_triage/commit/aa577859e5970bc1d27d970a8febc66307b1f256))
- Cgroup, systemd, and container collection modules ([b47d324](https://github.com/Dicklesworthstone/process_triage/commit/b47d324dbf0e6ffe98d35e4bc82129e93056214a))
- N_eff_cores CPU capacity derivation ([c741d81](https://github.com/Dicklesworthstone/process_triage/commit/c741d81e1cc4662b3009d46827f96bf3dffa7d49))

### Decision & Safety

- Pre-check safety gates for action execution ([ac27b12](https://github.com/Dicklesworthstone/process_triage/commit/ac27b124120fafdb9990d8a5d7cd7b1b10e2ac9a))
- Unified signature database for supervision detection ([3756121](https://github.com/Dicklesworthstone/process_triage/commit/37561214c446a9b63ab7ec50662bf988c52e37be))
- Container/K8s supervision detection ([92f547f](https://github.com/Dicklesworthstone/process_triage/commit/92f547ff871b2eb6bac8f10d4b44e3e88103c351))
- Systemd supervisor detection with actionable recommendations ([4c4f900](https://github.com/Dicklesworthstone/process_triage/commit/41c4f9000dd3c2d56b97392c0c97af8d3b2f6875))
- Goal-oriented optimization with greedy+ILP, preference learning ([fdf55cf](https://github.com/Dicklesworthstone/process_triage/commit/fdf55cf376114c08024feb607b0a3dca9713bb43))
- Wonham filtering + Gittins index scheduling ([7e693dc](https://github.com/Dicklesworthstone/process_triage/commit/7e693dc))
- Time-based notification ladder ([ee4273e](https://github.com/Dicklesworthstone/process_triage/commit/ee4273ebc75a7adf98914b4d013151eb0cec6f2f))

### TUI

- Interactive TUI with responsive layout, detail pane, and golden snapshot tests ([6d414eb](https://github.com/Dicklesworthstone/process_triage/commit/6d414eb719dbf38926b0271c68f95c12cd15bcf1))
- Plan execution pipeline with preview ([8537b3c](https://github.com/Dicklesworthstone/process_triage/commit/8537b3cd545ac0709b23daf1129c8e1d70e0efe5))
- Goal summary header in responsive layout ([13e2f85](https://github.com/Dicklesworthstone/process_triage/commit/13e2f857e8e2329bf235c9d1dd160f2e86f319bf))

### Fleet Mode

- SSH remote scanning ([356c7b9](https://github.com/Dicklesworthstone/process_triage/commit/356c7b9e524129ebacd1f07d9a35006d26b76d73))
- Fleet status/apply/report with session persistence ([e1b029c](https://github.com/Dicklesworthstone/process_triage/commit/e1b029cd1277e12a3cb4bc9984ffe4f18fb358ce))
- Transfer bundle system for cross-host prior/signature sharing ([b6bfb70](https://github.com/Dicklesworthstone/process_triage/commit/b6bfb70bb8f435e2ba09b3c69fad2fa850270c71))
- Pooled FDR selection for fleet-wide kill recommendations ([bda14e6](https://github.com/Dicklesworthstone/process_triage/commit/bda14e6fb26ce54d8b18f63cd0ebf39d0d159538))
- Discovery config, provider registry, and DNS scaffold ([e9bb497](https://github.com/Dicklesworthstone/process_triage/commit/e9bb497011523dff498631cca1354559d8205597))

### Agent / Robot Mode

- Agent-optimized robot mode for headless/automated operation ([5441428](https://github.com/Dicklesworthstone/process_triage/commit/54414289d196c9b5f3b4c87a20b3e84d0b39f650))
- MCP server for AI agent integration ([ef16403](https://github.com/Dicklesworthstone/process_triage/commit/ef164032015af5768052c9d02f2e0edad02ff9b0))
- Structured prediction schema, progressive disclosure UI, error handling with recovery hints ([7bca824](https://github.com/Dicklesworthstone/process_triage/commit/7bca824a75c83b1e443ee58cdc116633f501e527), [ea687ff](https://github.com/Dicklesworthstone/process_triage/commit/ea687ff69874367d46ed7d58174ac818f7ae9d26), [b7ae453](https://github.com/Dicklesworthstone/process_triage/commit/b7ae45386b44510551f490e22d9719c4b5992f57))
- Agent decision explanation API ([ec2555f](https://github.com/Dicklesworthstone/process_triage/commit/ec2555fa9a534b7f0277ac0713a47cfcce9ba3de))
- Watch command for continuous monitoring with notifications ([244940e](https://github.com/Dicklesworthstone/process_triage/commit/244940ea41e4263ad456b7c6f4b2bbeaf9eecec8))
- Session diff for comparing snapshots ([729b7ed](https://github.com/Dicklesworthstone/process_triage/commit/729b7ed2365d726a7d27cd67c194a931f6936cc0))

### Daemon

- Start/stop/status daemon commands (926 lines) ([b8ba187](https://github.com/Dicklesworthstone/process_triage/commit/b8ba18710ecb8fe0fe43b6087e3c6e84360a29fd))
- Prometheus metrics endpoint ([616e0d1](https://github.com/Dicklesworthstone/process_triage/commit/616e0d1a57dda66626e159ad410b48222f7ad58e))

### Installer

- `install.sh` with self-refresh mechanism and PATH management ([e554fc7](https://github.com/Dicklesworthstone/process_triage/commit/e554fc750a7c386f96df0b1ec44e99b23dee598e), [9cefab7](https://github.com/Dicklesworthstone/process_triage/commit/9cefab7b9702348d3563fbcd39bde07d3acfcaa6))
- `pt update` self-update command with checksum verification ([017e909](https://github.com/Dicklesworthstone/process_triage/commit/017e909cab13b65126e94f0316ee3caca16ce6fc), [9c41e39](https://github.com/Dicklesworthstone/process_triage/commit/9c41e39854bbe1d6c0e8e8400507c4f56c20ff93))
- ECDSA P-256 signature verification ([388430](https://github.com/Dicklesworthstone/process_triage/commit/388430024aa624cc9e0d608cc670a5c63ab55237))
- Atomic file replacement, bash syntax validation before replacement ([e90ac06](https://github.com/Dicklesworthstone/process_triage/commit/e90ac065dba6c8b395ef683fcb3b515c3cb9c7b1), [f8ce1da](https://github.com/Dicklesworthstone/process_triage/commit/f8ce1da6f40c0440b48a556b013996f51917d184))

---

## v1.0.0 -- 2026-01-14

Initial commit [`93843c6`](https://github.com/Dicklesworthstone/process_triage/commit/93843c6fcf52f99dfca3c578c84f03c5e302e30c). Bash-only prototype.

### Features

- Bash CLI with [gum](https://github.com/charmbracelet/gum) for interactive UI
- Multi-factor scoring heuristics for zombie/abandoned process detection
- Learning memory system with pattern normalization
- Safety-first kill sequence: SIGTERM before SIGKILL, confirmation required
- Auto-installs gum dependency if missing
- BATS test suite

### Files

- `pt` -- 578-line bash script
- `test/pt.bats` -- integration tests
- `AGENTS.md` -- agent coordination rules

---

## Version Timeline

| Tag | Date | GitHub Release | Commits from prior tag |
|-----|------|:-:|--:|
| v1.0.0 (initial) | 2026-01-14 | -- | 1 |
| v2.0.0 | 2026-02-13 | -- | ~830 |
| v2.0.1 | 2026-02-13 | -- | 2 |
| v2.0.2 | 2026-02-13 | -- | 2 |
| v2.0.3 | 2026-02-13 | -- | 2 |
| v2.0.4 | 2026-03-09 | Yes | 100+ |
| v2.0.5 | 2026-03-14 | Yes | 21 |

[Unreleased]: https://github.com/Dicklesworthstone/process_triage/compare/v2.0.5...HEAD
[v2.0.5]: https://github.com/Dicklesworthstone/process_triage/compare/v2.0.4...v2.0.5
[v2.0.4]: https://github.com/Dicklesworthstone/process_triage/compare/v2.0.3...v2.0.4
[v2.0.3]: https://github.com/Dicklesworthstone/process_triage/compare/v2.0.2...v2.0.3
[v2.0.2]: https://github.com/Dicklesworthstone/process_triage/compare/v2.0.1...v2.0.2
[v2.0.1]: https://github.com/Dicklesworthstone/process_triage/compare/v2.0.0...v2.0.1
[v2.0.0]: https://github.com/Dicklesworthstone/process_triage/compare/93843c6...v2.0.0
