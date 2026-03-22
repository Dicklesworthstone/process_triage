# Changelog

All notable changes to `pt` (process_triage) are documented in this file.

Versions marked **[GitHub Release]** have published artifacts on
[GitHub Releases](https://github.com/Dicklesworthstone/process_triage/releases).
Tags without that label are git-only tags with no corresponding release page.

Repository: <https://github.com/Dicklesworthstone/process_triage>

---

## [Unreleased] (after v2.0.5)

67 commits since v2.0.5 as of 2026-03-21.
Two major themes: **provenance-aware blast-radius estimation** and **installer hardening**.

### Provenance Engine (epic bd-ppcl)

A full provenance subsystem landed, giving `pt` the ability to answer
"what would break if I killed this?" with evidence-backed specificity.

- Blast radius, lineage, resource, and workspace evidence modules in pt-common ([c93fe27](https://github.com/Dicklesworthstone/process_triage/commit/c93fe27ee43f5d3c9920c325976644d315c604fc))
- Lineage and resource collectors with provenance E2E tests ([f1d87a0](https://github.com/Dicklesworthstone/process_triage/commit/f1d87a0899ab0fe3b29c9d2c569ce37e803c1eaa))
- Network resource collector module ([148f3a9](https://github.com/Dicklesworthstone/process_triage/commit/148f3a91395cb135f1799ac6a03f1f0e02ebcf99))
- Shared-resource provenance graph mapping lockfiles, sockets, and listeners ([efa8520](https://github.com/Dicklesworthstone/process_triage/commit/efa8520d389297b25f29c35c7fdd83c850f355ad))
- Provenance-aware direct-impact heuristics ([bdacc39](https://github.com/Dicklesworthstone/process_triage/commit/bdacc39dddd24b37bd4105c291418bf85652f8c2))
- Provenance continuity tracking across scans ([eb64cf2](https://github.com/Dicklesworthstone/process_triage/commit/eb64cf2f3f9d9d600252a82924942e4e60c5af64))
- Indirect-impact and uncertainty propagation ([7b4b297](https://github.com/Dicklesworthstone/process_triage/commit/7b4b29771a57c639df7c37ef8035ab55c0966848))
- Unified blast-radius estimator ([d9f7cf6](https://github.com/Dicklesworthstone/process_triage/commit/d9f7cf68cbb1a8c91e4b3ced47b3902c049c98f0))
- Blast-radius integration into scoring pipeline ([dfb04c5](https://github.com/Dicklesworthstone/process_triage/commit/dfb04c5b1f0320833d3851da5b9396c3ea6d1a19))
- Provenance explanation with counterfactual stories ([63b55f5](https://github.com/Dicklesworthstone/process_triage/commit/63b55f54c6ba9071106033ec00c0dc7e24e7703b))
- Structured output contract, narrative expansion, policy gates, and decision memory ([b3f3172](https://github.com/Dicklesworthstone/process_triage/commit/b3f31725d751f44902680d7ba636a8eaf9e97597))
- TUI provenance inspector with daemon alerts and fleet integration ([4b3761a](https://github.com/Dicklesworthstone/process_triage/commit/4b3761a467b0b39938491c0eb4e17e87a2141b9c), [6d396e8](https://github.com/Dicklesworthstone/process_triage/commit/6d396e8210f86368b8415d6803da57f775fbe508))

### Inference & Math

- Queueing-theoretic stall detection with causal snapshots and math proofs ([0744776](https://github.com/Dicklesworthstone/process_triage/commit/0744776f10bf654a85310dd3df73deb3d56ad56a))
- Load-dependent service rates in queueing model ([40ec904](https://github.com/Dicklesworthstone/process_triage/commit/40ec90411c082bce378a127faef2d5ad8ee1e559))
- Mondrian conformal risk control for robot mode ([3f1c17c](https://github.com/Dicklesworthstone/process_triage/commit/3f1c17cca5c95f2c6e86fecaca331c0f170e710d))
- Precomputed tables, stable distribution, and expanded posterior math in pt-math (+225 lines) ([9b9a9df](https://github.com/Dicklesworthstone/process_triage/commit/9b9a9df1c2e7fe196007776500546c8752c2465c))
- Major provenance expansion and posterior refinement in pt-common (+692 lines) ([4e9588f](https://github.com/Dicklesworthstone/process_triage/commit/4e9588f845fdc122ff8c307932d5a49f8482475c))
- Major CLI expansion and inference engine improvements (+632 lines) ([779c879](https://github.com/Dicklesworthstone/process_triage/commit/779c8794f09590112140fe71929ea98f045081f4))

### CLI & Session

- Evidence export and provenance query subcommands ([cd5ac6a](https://github.com/Dicklesworthstone/process_triage/commit/cd5ac6a948ec993a383e0d4d519d40e4982ce08b), [6bcd2d1](https://github.com/Dicklesworthstone/process_triage/commit/6bcd2d11250b7c476a61273e9a4665723ffa9276))
- Session diff engine with comprehensive diff tests (+382 lines) ([03385f4](https://github.com/Dicklesworthstone/process_triage/commit/03385f40dee2a9e7e8bf7938d5008e6365e6fa6e))

### Installer

- Overhauled installer with trajectory prediction tests and refined supervisor/trend logic ([4ee71ac](https://github.com/Dicklesworthstone/process_triage/commit/4ee71ac54e4bea8fbe5e6d5443eb85078d9a5062))
- Additional platform checks and recovery logic ([bc31d84](https://github.com/Dicklesworthstone/process_triage/commit/bc31d849740e626082aa46b1a26b768f2bc2dfe8))
- Additional validation and diagnostic checks ([f547007](https://github.com/Dicklesworthstone/process_triage/commit/f547007324c1597b6e0f3d5b64ca4ec3c932b802))

### Telemetry & Internals

- Wait-free prober, disruptor/recorder, and provenance privacy model ([ee5e773](https://github.com/Dicklesworthstone/process_triage/commit/ee5e773cda7ee47970fb28a62daa2c0be365f3c4))
- Provenance testing harness with fixtures and documentation ([a6ef08f](https://github.com/Dicklesworthstone/process_triage/commit/a6ef08fc53236d5a6c9413f7aa3dfdf5557967e0))
- Snapshot persistence with provenance integration (+183 lines) ([87a28aa](https://github.com/Dicklesworthstone/process_triage/commit/87a28aaed10bada6805f1fe56abcff8ffd7e446c))
- Provenance tracking and schema validation tests in pt-common ([46445a5](https://github.com/Dicklesworthstone/process_triage/commit/46445a5a216137e115807fbdc919de63840a755f))
- Replace raw i32 exit codes with typed ProcessExitStatus ([1ea2bc5](https://github.com/Dicklesworthstone/process_triage/commit/1ea2bc5a7c0191de693cad4d0f7d3bcca6719cf2))
- Harden proc-file reads with `from_utf8_lossy`, unify tool execution, validate MCP category filters ([f18bc17](https://github.com/Dicklesworthstone/process_triage/commit/f18bc1798c8aa485c55530430d601d1104f501b8))
- Strengthen provenance tracking, expand macOS collection, harden redaction ([5d56ea2](https://github.com/Dicklesworthstone/process_triage/commit/5d56ea2ff8c5c9d74c71e604cfef4ad27cd4b448))

### Fixes

- Correct M/M/1 tail probability formula P(N>=L)=rho^L ([a3e28eb](https://github.com/Dicklesworthstone/process_triage/commit/a3e28ebd54bb907b8fac97bcd2ecbf15c6caf85f))
- Use abstract queue-length for stall probability, fix `is_stalled` semantics ([c3551f7](https://github.com/Dicklesworthstone/process_triage/commit/c3551f7c08536949605160b88abce2b61161cc24))
- Avoid redundant PID prefix in blast-radius summary for isolated processes ([019bb4c](https://github.com/Dicklesworthstone/process_triage/commit/019bb4cf76f9d1cbfec540db77fddd43b49563bd))
- Refine provenance types and precomputed table precision ([2c74823](https://github.com/Dicklesworthstone/process_triage/commit/2c74823b1994bc884fa8bc62c92693a702b275ae))
- Add missing provenance fields to daemon test constructions ([e47f6af](https://github.com/Dicklesworthstone/process_triage/commit/e47f6af8d2d670c7605dd0f1888f1b72c86b2bb5))

### Testing

- Alien technology integration tests ([151cc6e](https://github.com/Dicklesworthstone/process_triage/commit/151cc6ec78e64cc05ca103a64f457d08672a3538))
- Blast-radius provenance regression suite ([8756a28](https://github.com/Dicklesworthstone/process_triage/commit/8756a2890b93b9d80dd63e9ea295905b9885f957))
- Resource-conflict provenance regression tests ([07f422f](https://github.com/Dicklesworthstone/process_triage/commit/07f422f901004aa005b1e15d9f208574e269a83d))
- E2E session diff tests (+172 lines) ([9c1bc1d](https://github.com/Dicklesworthstone/process_triage/commit/9c1bc1d7ad30ae92131a4e0ea62384b5c82086a5))
- Expanded bundle, evidence, and provenance tests (+620 lines) ([fff6773](https://github.com/Dicklesworthstone/process_triage/commit/fff6773803505ab889261bb9c159099bf07f383c))
- Real-system collection test module and expanded deep scan coverage ([dcbd04f](https://github.com/Dicklesworthstone/process_triage/commit/dcbd04f9e73990283bde63f47716052b20b66c68))

---

## [v2.0.5] -- 2026-03-14 **[GitHub Release]**

Tagged at [`772447b`](https://github.com/Dicklesworthstone/process_triage/commit/772447bdd1beef8100d60ebadd646a7637f5b14d).
Published 2026-03-14. 56 commits since v2.0.4.
Theme: **deep-scan/report commands, MCP expansion, macOS hardening, code quality sweep**.

Release artifacts: `pt-core-linux-x86_64`, `install.sh`, `pt` wrapper.

### Deep Scan & Reports

- Implement `pt deep` and `pt report` commands, deduplicate math into pt-math ([efa2e27](https://github.com/Dicklesworthstone/process_triage/commit/efa2e27d6d8e27560d626a574d30b99797f4d62f))
- `pt scan deep` alias routing to deep-scan subcommand ([a751c7c](https://github.com/Dicklesworthstone/process_triage/commit/a751c7c9d789534f7f74de4746c22dfe8f21b3b2))

### MCP & Agent Integration

- `pt_plan` MCP tool and just-in-time identity revalidation ([921ada4](https://github.com/Dicklesworthstone/process_triage/commit/921ada45e74c3c3f98fccfcf30323735a84e49ac))
- Wrapper-aware help in `pt` shell script ([9083eeb](https://github.com/Dicklesworthstone/process_triage/commit/9083eebb307d99eadff0d20dc57dbff77d5dd9e3))

### pt-math Extraction

- Add normal distribution and expand beta/gamma functions ([48bc89b](https://github.com/Dicklesworthstone/process_triage/commit/48bc89b12a937fa75691ffa7bded5f07dfe3af2f))
- Migrate statistical functions from pt-core into pt-math, harden mem-pressure scoring ([441848f](https://github.com/Dicklesworthstone/process_triage/commit/441848fc886540c7bddd1a17d3dabec294e6d122))

### Fixes

- Allocation-free critical-file detection, MCP tool fixes, pattern learning and beta math corrections ([e3c67d5](https://github.com/Dicklesworthstone/process_triage/commit/e3c67d5e3b39f0cd6fca66630fb64982b14a7055))
- Eliminate TOCTOU races and harden file-size limits across crates ([6977d1f](https://github.com/Dicklesworthstone/process_triage/commit/6977d1f1099b3cfcc97f3a825a3a123440459d1c))
- Use actual visible height for TUI page scrolling, restore `pt history/clear` ([2eafeaf](https://github.com/Dicklesworthstone/process_triage/commit/2eafeaf16e5f49a63e97861a17065c18b7d33bb0))
- Use `launchctl bootout` for launchd, fix `flip_conditions` log-odds math ([a48e8cf](https://github.com/Dicklesworthstone/process_triage/commit/a48e8cf808745b15b6517a786b3bcfd7438ed314))
- Release notes conditional on signing availability in CI ([db35e8c](https://github.com/Dicklesworthstone/process_triage/commit/db35e8ced8adc457e8f1b82527f3f2a181440fc6))

### macOS Hardening & Refactoring

- `ProcessNotFound` status, extend prechecks to macOS, harden signal/recovery logic ([3d2bb4b](https://github.com/Dicklesworthstone/process_triage/commit/3d2bb4bd18bf730c2ec7fb216ac808165f86fc68))
- Unify proc parsing, expand macOS collection, simplify deep_scan/ancestry ([81b7e6a](https://github.com/Dicklesworthstone/process_triage/commit/81b7e6ae9f7c1cc467c7208f107667b5df957e22))
- Simplify prechecks macOS path and clean up signal/recovery logic ([9d52638](https://github.com/Dicklesworthstone/process_triage/commit/9d526383b6f430c079e1bea613ca4d3d41bfb02c))
- Rustfmt pass, macOS environ support, type-safe signature categories ([87ebd15](https://github.com/Dicklesworthstone/process_triage/commit/87ebd1571fee34e4717bab971581039e79cbaa44))

### Code Quality

- Streamline supervision and session subsystems ([72165f8](https://github.com/Dicklesworthstone/process_triage/commit/72165f857b3a70991958382a7494787f0069226f))
- Deduplicate ps-line parsing, fix zero-parallel panic, harden JSONL serialization ([cd9fd6c](https://github.com/Dicklesworthstone/process_triage/commit/cd9fd6c4941177bffddac8401dedbc0e66257049))
- Eliminate redundant sorts in quantile functions, replace `unwrap` with safe patterns ([ac03456](https://github.com/Dicklesworthstone/process_triage/commit/ac034566781dfb1a42db1e7994bdd089d07c4b12))
- Remove redundant clones, streamline CLI dispatch and IPC buffering ([0f35f61](https://github.com/Dicklesworthstone/process_triage/commit/0f35f61028db63f35f2e57020789248268d2b95b))
- Replace `unwrap` with `expect`, use iterator in HSMM, promote regex to static `LazyLock` ([2b9d48b](https://github.com/Dicklesworthstone/process_triage/commit/2b9d48b41d49df85f0f8f8ab872b34882f6e08fd))
- Update agent_init, fleet, inference, learn, plugin modules and pt-bundle/pt-redact crates ([8eb778a](https://github.com/Dicklesworthstone/process_triage/commit/8eb778ab7ac06c11b4c17b0694d9ea46ac23d8e0))

### Licensing

- Update license to MIT with OpenAI/Anthropic Rider ([5aa9f89](https://github.com/Dicklesworthstone/process_triage/commit/5aa9f8993cbb652a06c67995bdc4de78054a8a6a))

### Testing

- E2E tests for outcome markers and zero-parallel SSH scan ([4493346](https://github.com/Dicklesworthstone/process_triage/commit/44933468fa86150d864e868775d0b4c8636745ef))
- Update recovery_tree bench and recovery_properties tests for typed ActionStatus ([72e4a6e](https://github.com/Dicklesworthstone/process_triage/commit/72e4a6e89a3f17d306602f73be51db884e3052de))
- Update wrapper, command, and integration test expectations ([2d8f419](https://github.com/Dicklesworthstone/process_triage/commit/2d8f419d0c27c687f35c2f91bd93a713580b9a5b))
- Update MCP protocol tests for 6-tool count ([dd67bcf](https://github.com/Dicklesworthstone/process_triage/commit/dd67bcf5e91834c9a577145436334ce0650f56b2))

---

## [v2.0.4] -- 2026-03-09 **[GitHub Release]**

Tagged at [`9444120`](https://github.com/Dicklesworthstone/process_triage/commit/9444120bd5390de6f5539d56bf522ca3ffb0caf1).
Published 2026-03-09. 111 commits since v2.0.3. Largest release by commit count.

First release with a six-platform binary matrix (Linux x86_64/aarch64
glibc + musl, macOS x86_64/aarch64) and ECDSA-signed artifacts.

### TUI Overhaul (ftui migration)

Complete migration from ratatui/crossterm to the ftui framework:

- Land ftui dependency gate and central Msg enum ([ba3c83c](https://github.com/Dicklesworthstone/process_triage/commit/ba3c83ce83811c051d93e40ad869bffe069a33fc))
- Port all widgets to ftui with dual rendering paths ([1e23c72](https://github.com/Dicklesworthstone/process_triage/commit/1e23c72ca1a383c6ae542cfad98adbcb6514a3cb))
- ftui model and key dispatch ([1cd02bf](https://github.com/Dicklesworthstone/process_triage/commit/1cd02bfbce1e26d0faca5bcefe41e9b3e7eea4fc))
- `--inline` ftui mode ([ee26706](https://github.com/Dicklesworthstone/process_triage/commit/ee267066deebf25d18bc5e8863ae60c79c0402bc))
- Remove ratatui/crossterm deps and ui-legacy dead code ([02f02cc](https://github.com/Dicklesworthstone/process_triage/commit/02f02cc62305a0af19fb4b59f59c5f85880ff4b5))
- 180 TUI unit tests (2.6x target) and KeyBindings tests ([1db9f1a](https://github.com/Dicklesworthstone/process_triage/commit/1db9f1ac05b95ec70a84a9c66b6520edfe68a922), [f72f785](https://github.com/Dicklesworthstone/process_triage/commit/f72f78590904e78d377b97c971544fa42d059e62))
- AuxPanel widget for wide-breakpoint action preview ([3484bba](https://github.com/Dicklesworthstone/process_triage/commit/3484bba987f7d97ad8711bdcc2fa12975083c5b3))
- Shell/TUI mode selection flags and tests ([dde7a2b](https://github.com/Dicklesworthstone/process_triage/commit/dde7a2bf5bc37f127b5c939ebefdc9806646f679))

### Accessibility

- `--accessible` flag and `PT_ACCESSIBLE` env var ([427cc49](https://github.com/Dicklesworthstone/process_triage/commit/427cc49e9aae2da1ae90dd8a8c7a867d302e5ecc))
- `--reduce-motion` flag and `REDUCE_MOTION` env var ([eb94773](https://github.com/Dicklesworthstone/process_triage/commit/eb947731d45b6fbd032dc30d772ea736257f1c3e))
- `--theme` and `--high-contrast` CLI flags ([e05d274](https://github.com/Dicklesworthstone/process_triage/commit/e05d274375c982e17927760ba5f045187a74781d))
- Command palette with screen reader announcements ([92bac98](https://github.com/Dicklesworthstone/process_triage/commit/92bac985c07b44d95bf3a462faaf6fcf1c01a65d))

### Inference & Decision Theory

- Wonham filtering + Gittins index scheduling ([7e693dc](https://github.com/Dicklesworthstone/process_triage/commit/7e693dcbd388ba25e2119ad9ddcd5e8cbf2177aa))
- Contextual bandits, drift detection, and session typestate system ([70352e2](https://github.com/Dicklesworthstone/process_triage/commit/70352e22b2ae3fe51c4252d6365e6c95e093896a))
- Inference ledger with structured evidence tracking and confidence scoring ([738f8c2](https://github.com/Dicklesworthstone/process_triage/commit/738f8c2982ade3b06a05337c0c5d4f9c3d49015b))
- Evidence glyph mapping for all feature types ([c13ab17](https://github.com/Dicklesworthstone/process_triage/commit/c13ab17df0ea083e1a28fda5757e532e3f7699d2))
- HSMM posterior transition fix and session diff stabilization ([a6009f7](https://github.com/Dicklesworthstone/process_triage/commit/a6009f7f0b6d8800a6f9699e54a46866e7d0fb4a))

### Installer & Release Infrastructure

- ECDSA P-256 signature verification wired into update flow ([6d8fc48](https://github.com/Dicklesworthstone/process_triage/commit/6d8fc480bb45292eaf7d51a894cf4e191e73271c))
- Rollback safety, CI release workflow, and comprehensive installer test coverage ([075236d](https://github.com/Dicklesworthstone/process_triage/commit/075236d5f94c0cdb1b45de6540263d6e1d868571))
- Make release signing optional when secret is absent ([9444120](https://github.com/Dicklesworthstone/process_triage/commit/9444120bd5390de6f5539d56bf522ca3ffb0caf1))
- Update macOS CI runners from deprecated macos-13 ([b51e016](https://github.com/Dicklesworthstone/process_triage/commit/b51e016d2daaaa07d77ea3e09adb76591a337246))
- Accept static-pie binaries in musl linking check ([b7352a4](https://github.com/Dicklesworthstone/process_triage/commit/b7352a40507e42cb87c70c162767a6c638a989ba))
- Harden release trust pinning and update path safety ([ded106a](https://github.com/Dicklesworthstone/process_triage/commit/ded106ac6f0e133ddfb8af0be871ccdca5fc5643))

### Security Hardening

- Cap KDF iterations, fix rate limiter TOCTOU race, prevent blast-radius overflow ([b5884eb](https://github.com/Dicklesworthstone/process_triage/commit/b5884eb1bd1d3860a7903b9bfc3d9a00f941362a))
- Fix safety, correctness, and security issues across 15 source files ([7e05f7d](https://github.com/Dicklesworthstone/process_triage/commit/7e05f7d918220e18d13ee2da0f4f51ad046e02e5))

### Correctness Fixes

- Fix 14 correctness and safety issues across inference, collection, redaction, and telemetry ([34c7f90](https://github.com/Dicklesworthstone/process_triage/commit/34c7f9046aaef70182a388475dc8da211c66f965))
- TTY/shell activity detection, conformal predictor self-call, HSMM duration tracking, LFP credal set allocation ([f29bf81](https://github.com/Dicklesworthstone/process_triage/commit/f29bf81a9c7b06966f588039c4549189409f36c3))
- Prevent panic on truncated `/proc/PID/stat` in ancestry parser ([630e4a8](https://github.com/Dicklesworthstone/process_triage/commit/630e4a88c63ffa5d5d65070a58bdc8bfdadb2265))
- Durable `sync_all` for alpha investing state, fix CVaR VaR tracking ([a7e3aa3](https://github.com/Dicklesworthstone/process_triage/commit/a7e3aa3a69b883a1eb6efbc4e2ab5243dcb3adf2))
- Correct policy pattern matching, guard against NaN loss, tolerate plugin BrokenPipe ([2021ad6](https://github.com/Dicklesworthstone/process_triage/commit/2021ad694e279e1ec32acf38c3ad033cefbd2db6))
- Relax resident-pages assertion for freshly spawned processes ([a6b6e90](https://github.com/Dicklesworthstone/process_triage/commit/a6b6e9026046d4986ee03bfd9fd98f6b2f1e926b))
- Correct off-by-one in `quick_scan.rs` minimum field check ([7ea1a1f](https://github.com/Dicklesworthstone/process_triage/commit/7ea1a1fc56e92d36119934e96b15a0be58d1291e))
- Lower macOS field-count threshold to match `macos.rs` ([91b669e](https://github.com/Dicklesworthstone/process_triage/commit/91b669e07f7641a96fe3d8cdf70a4829c9e9e31c))
- Serialize both CpuEvidence variants in evidence JSON ([0ea4070](https://github.com/Dicklesworthstone/process_triage/commit/0ea40707941827e759a63f08b1b7a3dea87e32c6))
- Include all evidence fields in `build_process_explanation` JSON ([bf26e29](https://github.com/Dicklesworthstone/process_triage/commit/bf26e290e2dabb2335b9b67d1eb4aff8b85d37b6))
- Sanitize EWMA alpha, guard infeasible credal sets, apply state-based action feasibility ([1cf5250](https://github.com/Dicklesworthstone/process_triage/commit/1cf5250))
- Prevent backup/rotation filename collisions ([b7c623c](https://github.com/Dicklesworthstone/process_triage/commit/b7c623c203cab5f6e259f5afba521830c54c840f))

### Plugin & Packaging

- Plugin system for custom evidence sources and action hooks ([4f1bddf](https://github.com/Dicklesworthstone/process_triage/commit/4f1bddf270f8ed8a5d215b83e2620b2070e7d253))
- Shell completions, Dockerfile, and justfile ([e371dd5](https://github.com/Dicklesworthstone/process_triage/commit/e371dd53712354c279b762bc4babd65123b3df21))
- Replay/simulation mode with snapshot recording and built-in scenarios ([5f46722](https://github.com/Dicklesworthstone/process_triage/commit/5f46722425c99effcdf9d33cfcefdbf70d215f4b))
- Query sessions subcommand with multi-format output ([6c20953](https://github.com/Dicklesworthstone/process_triage/commit/6c20953c6e58ede2ad4289856560224d6b912311))
- Toast notifications for async operation feedback ([179fa7c](https://github.com/Dicklesworthstone/process_triage/commit/179fa7c9ac7ae0e537a0abec50a9f5eba76dcda0))

### Benchmarks (Criterion)

Comprehensive benchmark suites added across all major subsystems:

- Decision engine: VOI, SPRT/GLR, CVaR, submodular selection, FDR, alpha-investing, sequential stopping, robot constraints, time-bound, DRO, dependency-loss, expected-loss, goal-plan, goal-progress, mem-pressure, rate-limit, respawn-loop, causal/load-aware/martingale, Wonham/Gittins, escalation, fleet-registry, fleet-pattern, fleet-FDR ([af71251](https://github.com/Dicklesworthstone/process_triage/commit/af71251977cf620d9ee052d1f81c0bc8f1d5b164) .. [1d26de0](https://github.com/Dicklesworthstone/process_triage/commit/1d26de0a78e2ee0057e9dad217187e780e87b44c))
- Inference: HSMM, robust inference, compound Poisson ([c15f2bc](https://github.com/Dicklesworthstone/process_triage/commit/c15f2bc5a8c317b8f51840ac18b1fdf2518ae13e))
- Action: recovery tree and session tracking ([92ddc43](https://github.com/Dicklesworthstone/process_triage/commit/92ddc43061605645ef62174ca618bddc0bb26c30))
- Supervision: signature matching, pattern learning, pattern stats ([37f796f](https://github.com/Dicklesworthstone/process_triage/commit/37f796fca151fa832a4d454d6e1b0ae367328f8c))
- Daemon: trigger evaluation and single-tick microbench ([215f1ed](https://github.com/Dicklesworthstone/process_triage/commit/215f1ed78e6820266f0e829cdf4473c8a56e703c), [faf7012](https://github.com/Dicklesworthstone/process_triage/commit/faf7012bc82cc594a6627e2b1c4748ff06d6fe0e))

### Property-Based Tests (proptest)

Exhaustive property tests added for mathematical invariants:

- Decision: FDR, alpha-investing, CVaR, SPRT/GLR, VOI, myopic policy, escalation, fleet, goal-plan, goal-progress, mem-pressure, rate-limit, respawn-loop, time-bound, DRO, dependency-loss, sequential stopping, robot constraints, causal/load-aware/martingale ([e03d81a](https://github.com/Dicklesworthstone/process_triage/commit/e03d81a3a3066904c4901a227cb45e98b6e2b6ea) .. [2980e4a](https://github.com/Dicklesworthstone/process_triage/commit/2980e4a8ecd4be6887c18c86552327a2ce949861))
- Inference: HSMM, robust inference, compound Poisson ([76944f6](https://github.com/Dicklesworthstone/process_triage/commit/76944f67d3da608d4b8cfb04b7f850abe308535d))
- Action: recovery tree, session, executor invariants ([59042e4](https://github.com/Dicklesworthstone/process_triage/commit/59042e4ed4d825743111eb902c1b61dca2b16553))
- Wonham filter and Gittins index ([89ee9ea](https://github.com/Dicklesworthstone/process_triage/commit/89ee9eaf3af9e5bdd509e5a672e27ae0d6019b54))

### Daemon Chaos Tests

- SIGTERM clean shutdown, SIGHUP reload, SIGKILL restart recovery, signal-storm resilience ([4326cb0](https://github.com/Dicklesworthstone/process_triage/commit/4326cb0d11232493983fbb5e5bce2ba5554618ff), [5ea655a](https://github.com/Dicklesworthstone/process_triage/commit/5ea655a9e615024dfdc6a5937da82f65a11cd9b8), [4694216](https://github.com/Dicklesworthstone/process_triage/commit/46942166e3c17d0ce44de751168a6fd1dad67b37), [012b873](https://github.com/Dicklesworthstone/process_triage/commit/012b87335ce930955ed125e1971636ffcc0fef07))

### Refactoring

- Migrate all references from `master` branch to `main` ([62c7ae4](https://github.com/Dicklesworthstone/process_triage/commit/62c7ae43be87b0378f38d491f26bfa762fcf15c7))
- Clippy and idiomatic-Rust cleanup across pt-core, pt-common, pt-config ([8b0e911](https://github.com/Dicklesworthstone/process_triage/commit/8b0e911379ecb8805fd3a6308fe0b27112fdc8f4))
- Resolve all clippy warnings and add category prior defaults ([89693cb](https://github.com/Dicklesworthstone/process_triage/commit/89693cb1a3382620ef6c285021ce3c2b3ad62a19))
- Remove deprecated `collect/repro_bug.rs` debugging leftover ([8559426](https://github.com/Dicklesworthstone/process_triage/commit/855942668c8a3a2eb8fb3fd584330eb1becf6e74))
- `dead_code` allow attribute cleanup audit ([53cae54](https://github.com/Dicklesworthstone/process_triage/commit/53cae54ea22a32b3fe0da33bc4011ed147b5dd82))

---

## [v2.0.3] -- 2026-02-13

Tagged at [`abe30a2`](https://github.com/Dicklesworthstone/process_triage/commit/abe30a22a5426b468f3f4f3d94962549dcad7d9e).
Git tag only (no GitHub Release page). Release-engineering fix to unblock cross-target builds.

### Changes

- Unblock cross-target builds for the release workflow ([abe30a2](https://github.com/Dicklesworthstone/process_triage/commit/abe30a22a5426b468f3f4f3d94962549dcad7d9e))
- TUI Toast notifications for async operation feedback ([179fa7c](https://github.com/Dicklesworthstone/process_triage/commit/179fa7c9ac7ae0e537a0abec50a9f5eba76dcda0))

---

## [v2.0.2] -- 2026-02-13

Tagged at [`fa2a64a`](https://github.com/Dicklesworthstone/process_triage/commit/fa2a64a564b93da308277409851e19877db5a20f).
Git tag only. Version bump for a release workflow retry.

### Changes

- Isolate cargo target dir in release workflow to fix parallel build conflicts ([addc1fc](https://github.com/Dicklesworthstone/process_triage/commit/addc1fc71f5a1fab8e40e751739276abfbbb850f))
- Version bump to 2.0.2 ([fa2a64a](https://github.com/Dicklesworthstone/process_triage/commit/fa2a64a564b93da308277409851e19877db5a20f))

---

## [v2.0.1] -- 2026-02-13

Tagged at [`956edd7`](https://github.com/Dicklesworthstone/process_triage/commit/956edd7a860c0e6376e3a752153d1494f84c4f3b).
Git tag only. CI verification pass.

### Changes

- Update Cargo.lock dependencies and sync beads issue tracker ([2db881b](https://github.com/Dicklesworthstone/process_triage/commit/2db881bc4ef3a567e591c71b3aae8af43a40e9c5))
- Close CI verification bead after all checks pass ([956edd7](https://github.com/Dicklesworthstone/process_triage/commit/956edd7a860c0e6376e3a752153d1494f84c4f3b))

---

## [v2.0.0] -- 2026-02-13

Tagged at [`f327f51`](https://github.com/Dicklesworthstone/process_triage/commit/f327f51781a5a6cf1bb84b9e765ac8f3ff1c15c1).
Git tag only. **Foundational release** -- a from-scratch rewrite of the original
bash script into a Rust workspace. 831 commits between the v1.0.0 prototype and
this tag, spanning 2026-01-14 through 2026-02-13.

### Architecture

Complete rewrite from a single bash script into a multi-crate Rust workspace:

- **pt-core** -- CLI binary, inference engine, process collection, action executor, TUI, daemon, fleet mode
- **pt-common** -- Shared types: process identity, evidence structures, capabilities, categorization
- **pt-math** -- Numerically stable math: Beta/Gamma distributions, Dirichlet-Multinomial posterior, log-domain normalization, hazard rate utilities ([3957bab](https://github.com/Dicklesworthstone/process_triage/commit/3957bab97b62564ea1ae5da36114201ca08e21ad), [f1b0a0b](https://github.com/Dicklesworthstone/process_triage/commit/f1b0a0b9a65996784aae2034578326197c34d861), [62701e2](https://github.com/Dicklesworthstone/process_triage/commit/62701e2aaef46ea1e0a49496dd0a7544f3b5048f))
- **pt-config** -- Configuration loading and schema validation ([1c8623a](https://github.com/Dicklesworthstone/process_triage/commit/1c8623aacb1db4cddd3871cc64d3fd0213557adc))
- **pt-telemetry** -- Batched Parquet writer with crash safety, shadow mode observation storage ([25d9f24](https://github.com/Dicklesworthstone/process_triage/commit/25d9f24b2d7f4d86717a04c7e9f7af6a608b95a1), [1566718](https://github.com/Dicklesworthstone/process_triage/commit/1566718ea61079a3ae19637c35bbe0324e04fbf0))
- **pt-bundle** -- Session bundle serialization for agent/fleet exchange
- **pt-redact** -- PII redaction for safe session sharing ([ade0fc5](https://github.com/Dicklesworthstone/process_triage/commit/ade0fc5))
- **pt-report** -- HTML/markdown report generation

Workspace scaffolded at [e6d8c5f](https://github.com/Dicklesworthstone/process_triage/commit/e6d8c5fe29ecf6effdd1455db7abbc88ced12c6e).

### Bayesian Inference Engine

40+ statistical models with conjugate posteriors for process classification:

- Core posterior computation and conjugate models ([e274f1a](https://github.com/Dicklesworthstone/process_triage/commit/e274f1a78af884bc716668166395770b86d803ba))
- Conformal prediction module with distribution-free coverage guarantees ([64ce642](https://github.com/Dicklesworthstone/process_triage/commit/64ce642eda68ef31969d3242c30613bc6648b71d))
- Evidence ledger for full classification explainability ([5c192ce](https://github.com/Dicklesworthstone/process_triage/commit/5c192ce9589b76eea49b658a0e46c3aad6a50902))
- CTW prequential predictor for sequence anomaly detection ([740e5c3](https://github.com/Dicklesworthstone/process_triage/commit/740e5c3a183a03a298a01bbfc4f66a2f89aa5dad))
- Bayes factor module, alpha-investing for multiple testing ([9da6c13](https://github.com/Dicklesworthstone/process_triage/commit/9da6c1314ba6f9a65732a8a784dc1469a2553509))
- Martingale concentration bounds ([39bfae9](https://github.com/Dicklesworthstone/process_triage/commit/39bfae9a8a0152e3582dd2060fff54b19217c6e0))
- What-if flip-conditions explainer ([ba24374](https://github.com/Dicklesworthstone/process_triage/commit/ba243749fde0ea9e588a4f9f113908cffc59ebe9))
- Confidence visualization with safety/gate badges ([3b0655b](https://github.com/Dicklesworthstone/process_triage/commit/3b0655bd21ea0e72406b2ead4a40100885c756f6))
- Streaming sketches for high-rate events ([0bee36c](https://github.com/Dicklesworthstone/process_triage/commit/0bee36c9b6280fc8ba3bac626b9b9295eabbdcc5))
- Harden BOCPD against NaN, increase max run length ([5fd25ad](https://github.com/Dicklesworthstone/process_triage/commit/5fd25ad1bd012d2a94c0230f66857dcd2047c4f3))

### Process Collection

- Deep scan with full `/proc` introspection: sched info, environ, open FDs, network connections ([04f2ac0](https://github.com/Dicklesworthstone/process_triage/commit/04f2ac098eb8c3382a42323f6e9fee3378ff93e3), [74099ff](https://github.com/Dicklesworthstone/process_triage/commit/74099ff0146b2684279bc4d8ed52e4620b4fa116))
- CPU tick-delta features (k_ticks/n_ticks/u/u_cores) ([7d9c4fb](https://github.com/Dicklesworthstone/process_triage/commit/7d9c4fb2ae2aec2cffd07077eb888ca5d6ff22e4))
- GPU process detection for CUDA and ROCm ([e78bf71](https://github.com/Dicklesworthstone/process_triage/commit/e78bf71d2a6d0973732c7e13a95b40211133530a))
- Incremental scanning engine ([aa57785](https://github.com/Dicklesworthstone/process_triage/commit/aa577859e5970bc1d27d970a8febc66307b1f256))
- Cgroup, systemd, and container collection modules ([b47d324](https://github.com/Dicklesworthstone/process_triage/commit/b47d324dbf0e6ffe98d35e4bc82129e93056214a))
- N_eff_cores CPU capacity derivation ([c741d81](https://github.com/Dicklesworthstone/process_triage/commit/c741d81e1cc4662b3009d46827f96bf3dffa7d49))
- User-intent/context features ([4857449](https://github.com/Dicklesworthstone/process_triage/commit/4857449ff305f68253fa24012798781af94997ad))
- Command and CWD category taxonomies ([3adf6b0](https://github.com/Dicklesworthstone/process_triage/commit/3adf6b083f2c8d3fb43fd511b2a583adb8246648))
- Structured logging foundation with JSONL support ([d082d82](https://github.com/Dicklesworthstone/process_triage/commit/d082d825b1fe03445dd5bdd09952feea87b09d4c))

### Decision & Safety

- Pre-check safety gates for action execution ([ac27b12](https://github.com/Dicklesworthstone/process_triage/commit/ac27b124120fafdb9990d8a5d7cd7b1b10e2ac9a))
- Recovery tree executor and requirement checking ([d859f12](https://github.com/Dicklesworthstone/process_triage/commit/d859f12622bc818c8e261b60ec562ab902a10e51))
- Extended action system: renice, resume, freeze, supervisor support ([b2f4829](https://github.com/Dicklesworthstone/process_triage/commit/b2f48294d7b9d2723d1740db648c34dfde66c083))
- Cgroup v2 CPU throttling and freeze actions ([7ac122b](https://github.com/Dicklesworthstone/process_triage/commit/7ac122bb65fa461293bab763f48568b10808ba14))
- Confidence-bounded automation controls for `--robot` mode ([443664c](https://github.com/Dicklesworthstone/process_triage/commit/443664c4f69d5cbe8a1ce3d5ab7b16b897cbef98))
- Critical file inflation for data-loss safety gate ([a6f16e6](https://github.com/Dicklesworthstone/process_triage/commit/a6f16e66ee925fa1e8c7e086d22333e39b39c3df))
- Dependency-weighted loss scaling ([1d64a6f](https://github.com/Dicklesworthstone/process_triage/commit/1d64a6ff101c49efc55af5d3928ba891048976fb))
- Goal-oriented optimization with greedy+ILP and preference learning ([fdf55cf](https://github.com/Dicklesworthstone/process_triage/commit/fdf55cf376114c08024feb607b0a3dca9713bb43))
- Time-based notification escalation ladder with persistence and desktop delivery ([ee4273e](https://github.com/Dicklesworthstone/process_triage/commit/ee4273ebc75a7adf98914b4d013151eb0cec6f2f), [b6d184c](https://github.com/Dicklesworthstone/process_triage/commit/b6d184c))

### Supervision Detection

- Unified signature database with comprehensive tests ([3756121](https://github.com/Dicklesworthstone/process_triage/commit/37561214c446a9b63ab7ec50662bf988c52e37be))
- Systemd supervisor detection with actionable recommendations ([41c4f90](https://github.com/Dicklesworthstone/process_triage/commit/41c4f9000dd3c2d56b97392c0c97af8d3b2f6875))
- Container/K8s supervision detection ([92f547f](https://github.com/Dicklesworthstone/process_triage/commit/92f547ff871b2eb6bac8f10d4b44e3e88103c351))
- App-level supervisor detection (PM2, supervisord, nodemon, forever) ([b57c23d](https://github.com/Dicklesworthstone/process_triage/commit/b57c23dbfb4f26cef343bdaf6fc8123910726270))
- Signature import subcommand and bundle sharing ([c7b30a5](https://github.com/Dicklesworthstone/process_triage/commit/c7b30a5cd8efe032f1299c3c78b7b8c77f1bf6c0))

### Interactive TUI

- Major TUI overhaul: responsive layout, rich detail pane, golden snapshot tests ([6d414eb](https://github.com/Dicklesworthstone/process_triage/commit/6d414eb719dbf38926b0271c68f95c12cd15bcf1))
- Plan execution pipeline with preview ([8537b3c](https://github.com/Dicklesworthstone/process_triage/commit/8537b3cd545ac0709b23daf1129c8e1d70e0efe5))
- Goal summary header in responsive layout ([13e2f85](https://github.com/Dicklesworthstone/process_triage/commit/13e2f857e8e2329bf235c9d1dd160f2e86f319bf))
- Execute action handler for selected processes ([a99d1c4](https://github.com/Dicklesworthstone/process_triage/commit/a99d1c47b8e06d5bba08ef7efded4a4cc0023f6f))
- Deep scan signals wired into interactive mode ([9293097](https://github.com/Dicklesworthstone/process_triage/commit/9293097baba46f1fb10cc0a66e606aa2ef1ae91f))

### Fleet Mode

- SSH remote scanning ([356c7b9](https://github.com/Dicklesworthstone/process_triage/commit/356c7b9e524129ebacd1f07d9a35006d26b76d73))
- Fleet status/apply/report with session persistence ([e1b029c](https://github.com/Dicklesworthstone/process_triage/commit/e1b029cd1277e12a3cb4bc9984ffe4f18fb358ce))
- Transfer bundle system for cross-host prior/signature sharing ([b6bfb70](https://github.com/Dicklesworthstone/process_triage/commit/b6bfb70bb8f435e2ba09b3c69fad2fa850270c71))
- Fleet transfer subcommands and fleet-wide reporting CLI ([f4a30f8](https://github.com/Dicklesworthstone/process_triage/commit/f4a30f8947d76407f8ee592096694c392b0d9eae))
- Pooled FDR selection for fleet-wide kill recommendations ([bda14e6](https://github.com/Dicklesworthstone/process_triage/commit/bda14e6fb26ce54d8b18f63cd0ebf39d0d159538))
- Discovery config, provider registry, and DNS scaffold ([e9bb497](https://github.com/Dicklesworthstone/process_triage/commit/e9bb497011523dff498631cca1354559d8205597))

### Agent / Robot Mode

- Agent-optimized robot mode for headless/automated operation ([5441428](https://github.com/Dicklesworthstone/process_triage/commit/54414289d196c9b5f3b4c87a20b3e84d0b39f650))
- MCP server for AI agent integration ([ef16403](https://github.com/Dicklesworthstone/process_triage/commit/ef164032015af5768052c9d02f2e0edad02ff9b0))
- Structured prediction schema and progressive disclosure UI ([7bca824](https://github.com/Dicklesworthstone/process_triage/commit/7bca824a75c83b1e443ee58cdc116633f501e527), [ea687ff](https://github.com/Dicklesworthstone/process_triage/commit/ea687ff69874367d46ed7d58174ac818f7ae9d26))
- Agent decision explanation API ([ec2555f](https://github.com/Dicklesworthstone/process_triage/commit/ec2555fa9a534b7f0277ac0713a47cfcce9ba3de))
- Structured agent error handling with recovery hints ([b7ae453](https://github.com/Dicklesworthstone/process_triage/commit/b7ae45386b44510551f490e22d9719c4b5992f57))
- Watch command for continuous monitoring with notifications ([244940e](https://github.com/Dicklesworthstone/process_triage/commit/244940ea41e4263ad456b7c6f4b2bbeaf9eecec8))
- Session diff for comparing snapshots (`pt diff`) ([729b7ed](https://github.com/Dicklesworthstone/process_triage/commit/729b7ed2365d726a7d27cd67c194a931f6936cc0))
- Structured progress events during plan execution ([cff9856](https://github.com/Dicklesworthstone/process_triage/commit/cff9856b95157e7a62210da272bc7a2489d7c62d))
- `pt agent explain`, `pt agent sessions` commands ([b6c88c4](https://github.com/Dicklesworthstone/process_triage/commit/b6c88c429a12258b7ebdb061665b0b5ed156707f), [949df83](https://github.com/Dicklesworthstone/process_triage/commit/949df83b1921a41ceae61c20ba79d0cbaa70a705))
- `--label` flag for agent plan command ([82a3b2a](https://github.com/Dicklesworthstone/process_triage/commit/82a3b2a))
- Min-age pre-filtering and enriched summary metadata ([20ad841](https://github.com/Dicklesworthstone/process_triage/commit/20ad841))

### Daemon

- Start/stop/status daemon commands (926 lines) ([b8ba187](https://github.com/Dicklesworthstone/process_triage/commit/b8ba18710ecb8fe0fe43b6087e3c6e84360a29fd))
- Prometheus metrics endpoint ([616e0d1](https://github.com/Dicklesworthstone/process_triage/commit/616e0d1a57dda66626e159ad410b48222f7ad58e))
- Calibrate score bucket breakdown and bias sections in markdown report ([6619dda](https://github.com/Dicklesworthstone/process_triage/commit/6619dda3d8161b95dfccd0cfb9339f565eec2928))

### Installer

- `install.sh` with self-refresh mechanism and PATH management ([e554fc7](https://github.com/Dicklesworthstone/process_triage/commit/e554fc750a7c386f96df0b1ec44e99b23dee598e), [9cefab7](https://github.com/Dicklesworthstone/process_triage/commit/9cefab7b9702348d3563fbcd39bde07d3acfcaa6))
- `pt update` self-update command with checksum verification ([017e909](https://github.com/Dicklesworthstone/process_triage/commit/017e909cab13b65126e94f0316ee3caca16ce6fc), [9c41e39](https://github.com/Dicklesworthstone/process_triage/commit/9c41e39854bbe1d6c0e8e8400507c4f56c20ff93))
- ECDSA P-256 signature verification ([3884300](https://github.com/Dicklesworthstone/process_triage/commit/388430024aa624cc9e0d608cc670a5c63ab55237))
- Atomic file replacement, bash syntax validation before replacement ([e90ac06](https://github.com/Dicklesworthstone/process_triage/commit/e90ac065dba6c8b395ef683fcb3b515c3cb9c7b1), [f8ce1da](https://github.com/Dicklesworthstone/process_triage/commit/f8ce1da6f40c0440b48a556b013996f51917d184))
- HTTP redirect-based version checking ([8a0a942](https://github.com/Dicklesworthstone/process_triage/commit/8a0a9428ca72bca04906feb5aeef0c6ba958b14b))
- pt-install-tools for maximal instrumentation ([5a0a7e8](https://github.com/Dicklesworthstone/process_triage/commit/5a0a7e8ad885d19969ab01888cd4ec0bd5f60caf))

### Testing Infrastructure

Over 600 tests added across the stack:

- 68 E2E TUI workflow tests with PTY recording ([7141e22](https://github.com/Dicklesworthstone/process_triage/commit/7141e22))
- 53 MCP protocol compliance tests ([e46c954](https://github.com/Dicklesworthstone/process_triage/commit/e46c954))
- 50 container and GPU detection integration tests ([8f06a06](https://github.com/Dicklesworthstone/process_triage/commit/8f06a06))
- 44 fleet mode integration tests ([2be7eee](https://github.com/Dicklesworthstone/process_triage/commit/2be7eee))
- 26 E2E installer lifecycle tests ([d73027b](https://github.com/Dicklesworthstone/process_triage/commit/d73027b))
- Comprehensive BATS test suites ([4ce5190](https://github.com/Dicklesworthstone/process_triage/commit/4ce51907c3cc1a76b149f9b6d33ca05007864968))
- No-mock integration tests across inference, safety gates, decision modules ([cc790ef](https://github.com/Dicklesworthstone/process_triage/commit/cc790efa77de7d96ff382bcf804c385fe50bde19))
- Agent CLI contract tests and JSON schemas ([d949ff4](https://github.com/Dicklesworthstone/process_triage/commit/d949ff460caadfb5ccaea03c94758327241694ed))
- Inline test expansion: 500+ new inline tests across pattern learning, prechecks, evidence ledger, verify, session, fleet, shadow, agent config, signature CLI, and action executor

### Design Specification

Before writing any code, 40+ specification documents were authored defining:

- Comprehensive Bayesian inference design ([bb141d6](https://github.com/Dicklesworthstone/process_triage/commit/bb141d64642ae4fcd315821bbf6360e60e13eddf))
- Advanced stochastic models and instrumentation ([8393942](https://github.com/Dicklesworthstone/process_triage/commit/8393942150eb54db63b0ec8a390291a3a0839d50))
- Multiple-testing safety, active sensing, streaming algorithms ([53e18b9](https://github.com/Dicklesworthstone/process_triage/commit/53e18b91cc77b2a9b200ae6edf3ba16f67dbdd9a))
- Agent CLI contract and session bundles ([d6ec6c1](https://github.com/Dicklesworthstone/process_triage/commit/d6ec6c1da3d53046cbccfac969e4a04c5e69195e))
- Fleet mode, pattern library, predictive analysis ([fc13488](https://github.com/Dicklesworthstone/process_triage/commit/fc13488a0427ee8dcbc9810e18b03e05e8044c68))
- Package architecture and CLI surface ([ab8820e](https://github.com/Dicklesworthstone/process_triage/commit/ab8820e33533595c4988df7f122720fc1a7c95dc), [e110122](https://github.com/Dicklesworthstone/process_triage/commit/e1101229abfcbbfc565710a26649fabc3c68c98a))
- Conformal prediction, VOI-driven probe selection, anytime-valid gates ([859d547](https://github.com/Dicklesworthstone/process_triage/commit/859d547048558e5ac1a35026a5dc2c9c346afa6d))

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
| v2.0.0 | 2026-02-13 | -- | 831 |
| v2.0.1 | 2026-02-13 | -- | 2 |
| v2.0.2 | 2026-02-13 | -- | 2 |
| v2.0.3 | 2026-02-13 | -- | 2 |
| v2.0.4 | 2026-03-09 | Yes | 111 |
| v2.0.5 | 2026-03-14 | Yes | 56 |

[Unreleased]: https://github.com/Dicklesworthstone/process_triage/compare/v2.0.5...HEAD
[v2.0.5]: https://github.com/Dicklesworthstone/process_triage/compare/v2.0.4...v2.0.5
[v2.0.4]: https://github.com/Dicklesworthstone/process_triage/compare/v2.0.3...v2.0.4
[v2.0.3]: https://github.com/Dicklesworthstone/process_triage/compare/v2.0.2...v2.0.3
[v2.0.2]: https://github.com/Dicklesworthstone/process_triage/compare/v2.0.1...v2.0.2
[v2.0.1]: https://github.com/Dicklesworthstone/process_triage/compare/v2.0.0...v2.0.1
[v2.0.0]: https://github.com/Dicklesworthstone/process_triage/compare/93843c6...v2.0.0
