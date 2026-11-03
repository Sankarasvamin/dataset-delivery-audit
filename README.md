# dataset-delivery-audit

- 版本：`0.2.0`
- 状态：`IN_PROGRESS`
- 远程仓库：待定（本阶段不初始化 Git、不提交、不上传）

`dataset-delivery-audit` 是独立的数据交付审计仓库。它对多数据集交付目录执行文件盘点、流式 SHA-256、完整性、压缩包、格式编码、RecordV1 Schema、内容样本、重复版本、时间覆盖、资源依赖和溯源审计，并把问题关联到可复核的结构化证据。现实工作中，交付目录可能同时包含漏件、坏包、历史格式漂移、内容异常、重复版本和证据断链；本仓库将这些匿名化为确定性合成案例，不含公司数据、私人数据或线上请求。

本仓库只检查和报告，不修复、删除、移动、覆盖或解压交付文件；也不重新清洗正文、重新去重、改变 canonical、修改质量评分或重新运行类别消融。

## 四仓关系

1. [corpus-preprocessing-core](https://github.com/Sankarasvamin/corpus-preprocessing-core) `v0.3.0`：数据接入、解析、抽样与清洗。
2. [text-dedup-canonicalization](https://github.com/Sankarasvamin/text-dedup-canonicalization) `v0.4.0`：精确/模糊去重、strict STAR 与 canonical。
3. [corpus-quality-evaluation](https://github.com/Sankarasvamin/corpus-quality-evaluation) `v0.2.0`：canonical 质量评分、三分类、人工校准 pilot 与类别消融。
4. `dataset-delivery-audit`：交付文件、归档、格式编码、Schema、内容样本及上下游证据审计。

仓库间只通过公开 README、版本化契约和合成数据建立关系。`contracts/record-v1.schema.json` 逐字节来自 `corpus-preprocessing-core v0.3.0`，SHA-256 为 `a47eae12eb1898f6c34c1af7bbae29ef78f888b71506befda1586d5ec923883c`；本仓库不改写该契约。`ING-09 Schema 与历史格式漂移` 在这里通过 `ISS-04` 检查，而不是回写 preprocessing 仓库。

## Contract-first

- `DeliveryExpectationV1`：交付方对 delivery、dataset、相对路径、格式、编码、Schema/version，以及可选 size/hash/record count 的声明。
- `FileInventoryV1`：root-relative POSIX path、entry type、字节数、SHA-256、扩展名、检测格式、编码状态、空文件、归档与重复内容组。
- `IssueV1`：确定性 issue ID、`ISS-01～04`、machine code、severity、相对定位、结构化 expected/observed evidence 和 remediation hint。
- `IssueV2`：向后兼容地支持 `ISS-01～09`，增加 record、抽样层、evidence scope 和 sample-plan 指纹；不改写 IssueV1。
- `RecordV1`：公开上游契约的字节级快照。
- `SamplePlanV1`、`CanonicalDecisionV1`、`QualityScoreV1`：分别逐字节来自三个公开上游版本，SHA-256 为 `77cd0b0b7713b06fa552cc4345673f0072aa628f0f252665416acc3ba6abe048`、`7a2deb50607f38cbac80c24bd1ee57222ebfc3c50c7ad7540e0ed24600fe256e`、`6c618df8e2583dea4b9a64ca1fcfdfc86ae17a0b1dfd8672f6a27ca928a96adf`。

缺少 expectation 时仍可盘点实际文件，但不能知道交付方原本承诺的文件、size、hash 或记录数，因此不会猜测 `missing_required_file`、`unexpected_file` 或统计不一致。issue ID 来自规范化证据的 SHA-256，不使用 UUID、时间戳、inode、用户名或绝对路径。

## Python 与 Rust 分工

Python 和 Rust 都以单线程、稳定路径排序、不跟随 symlink 的方式递归扫描，流式计算文件大小和 SHA-256，并输出同字段 `FileInventoryV1`。Rust 只使用 `std::fs`、`serde`、`serde_json` 和 `sha2`；Python 只使用标准库。

只有 Python 负责 expectation 对账、ZIP/TAR/GZIP、UTF-8、JSON/JSONL/TSV/HTML、RecordV1、Issue、内容分层抽样、ISS-05～09、summary 和 run manifest。Rust 在阶段 2 不增加内容审计能力，仍只负责阶段 1 文件扫描/hash parity。没有第二套扫描器、清洗器、去重器、质量评分器、通用规则引擎、第三方编码猜测器、数据库或 Web UI。

## 阶段 1 问题范围

### ISS-01 物理文件

`missing_required_file`、`unexpected_file`、`empty_file`、`size_mismatch`、`sha256_mismatch`、`duplicate_content`、`unsupported_entry_type`、`unsafe_nested_git`。

missing 只来自 expectation；重复内容使用完整 SHA-256 和稳定路径组，不按文件名猜测；所有问题只报告，不做物理处置。

### ISS-02 压缩包

`archive_integrity_failure`、`archive_crc_failure`、`archive_encrypted`、`archive_empty`、`archive_truncated`、`archive_unsafe_member_path`、`archive_limit_exceeded`、`archive_extension_mismatch`。

支持 `.zip`、`.tar`、`.tar.gz/.tgz` 和 `.gz`。归档不落盘，不信任 member path；拒绝绝对路径、`..` 和目录逃逸。member 数、单 member 展开字节和总展开字节均受配置限制；加密包只报告，疑似炸弹先停止深入读取，单个坏包不会中止其他文件。

### ISS-03 格式与编码

`format_extension_mismatch`、`invalid_utf8`、`unexpected_utf8_bom`、`json_parse_failure`、`jsonl_parse_failure`、`tsv_column_mismatch`、`unsupported_format`、`binary_content_in_text_file`。

JSONL 按行继续，Issue 只保存行号和结构证据，不默认复制坏行正文；TSV 使用标准库 `csv`，支持带引号的 tab。非 UTF-8 只报告无效编码，不武断猜成 GBK。HTML 只检查 UTF-8 和基本格式边界，不判断正文质量。

### ISS-04 Schema 与历史版本

`schema_missing_required_field`、`schema_type_mismatch`、`schema_version_missing`、`schema_version_unsupported`、`schema_unknown_field`、`schema_record_count_mismatch`、`schema_mixed_versions`。

required/type 来自提交的 RecordV1；允许版本和未知字段策略由 `configs/audit-v1.json` 明确控制。失败行隔离后继续审计，不补字段、不清洗、不迁移历史版本。

## 确定性合成交付包

`scripts/generate_fixtures.py` 使用固定 seed `20260822` 生成两套匿名 delivery：

| delivery | dataset | 文件 | inventory entries | 注入/issue |
|---|---:|---:|---:|---:|
| valid | 3 | 8 | 11 | 0 |
| problem | 4 | 31（30 regular + 1 symlink） | 37 | 32 |

格式覆盖 JSON、JSONL、TSV、HTML、ZIP、TAR、TGZ 和 GZIP。`fixtures/generated/injection-truth.json` 保存 32 个独立稳定注入：`ISS-01/02/03/04` 各 8 个；每项带 injection ID、定位和 fixture fingerprint。fixture fingerprint 为 `sha256:b4abd4b3deb38501fde5e5a36b9cac9e215abee96afe922c6a1440c647114c0b`。ZIP member 时间固定，正序/逆序创建两次逐字节一致。

合法 delivery 实际结果为 8 个 regular files、3 个 dataset、0 issue，`BLOCKER/ERROR/WARNING/INFO` 均为 0；输出 fingerprint 为 `sha256:361e49103b88558ffb9227ee016d1950078f8677fb697ee8524cb1362d5f2244`。

问题 delivery 实际结果为 30 个 regular files、4 个 dataset、32 个 issue：`ISS-01～04` 各 8，severity 为 `BLOCKER=4`、`ERROR=24`、`WARNING=4`、`INFO=0`。除 `schema_version_unsupported` 因独立 unsupported 与 mixed-version 行命中 2 次外，其余 machine code 各命中 1 次；输出 fingerprint 为 `sha256:e582bf3bfccf4822c8994b1c8a64e8d3bc1e7e1d700f2cab396fca21df8c610b`。实际 issue locator 与 injection truth 完全一致，没有 truth 之外的 ERROR/BLOCKER。

## 阶段 2：ISS-05～09

### 确定性分层抽样

`configs/content-sample-plan-v1.json` 固定 seed `20260822`，按 `dataset_id × record_type × event month` 分层，使用 `minimum_then_proportional` 和每层最少 2 条；null、非法和缺失日期分别进入稳定哨兵层。选择键为 `SHA-256(seed | dataset_id | record_type | event_month | record_id)`，不使用 Python `hash()`、问题 truth 或 ID 前缀。只有需要正文的 `ISS-05` 和 `ISS-08` 使用抽样；`ISS-06/07/09` 使用全量 metadata/index。当前小型合成包全部入样，但走的是同一分配代码路径：valid `population=12 / sample=12 / strata=12`，problem `population=54 / sample=54 / strata=23`。本阶段只报告覆盖，不将样本外推为总体问题率或置信区间。

### ISS-05 内容问题（sampled content）

`content_empty_body`、`content_noninformative_body`、`content_template_noise`、`content_suspected_truncation`、`content_field_misalignment`、`content_repeated_fragment`。

规则只使用可解释的 Unicode 计数、配置化 literal/regex、显式截断 marker/metadata/最低长度、明确字段交换和相邻重复片段。`content_suspected_truncation` 是保守启发式，不等于已经证明文件损坏；扫描器不重新清洗或删除正文。

### ISS-06 重复与版本（full metadata scan）

`record_exact_duplicate`、`duplicate_within_dataset`、`duplicate_across_datasets`、`source_identity_multiple_versions`、`version_content_conflict`、`canonical_group_multiple_members_delivered`、`canonical_nonselected_member_delivered`、`record_near_duplicate_evidence`。

本仓库只计算原值 `clean_text` 的完整 SHA-256 和来源身份 tuple。near-duplicate 只消费上游 `CanonicalDecisionV1 exact_fuzzy` 证据，不重算 MinHash、LSH、STAR、canonical 或 fuzzy score；缺少证据时不猜测模糊重复。

### ISS-07 时间覆盖（full metadata scan）

`event_date_missing`、`event_date_invalid`、`event_date_outside_expected_range`、`event_date_future_as_of`、`dataset_time_window_empty`、`date_conflict_with_partition`、`source_identity_date_conflict`。

日期只通过标准库 `datetime.date` 和配置中的固定 `as_of_date=2026-08-22`、范围及预声明窗口判断，不读取系统今天日期，也不从观察到的相邻日期猜测空窗。summary 按 dataset、category、record type 和 month 计数，但不计算时间覆盖可用率。

### ISS-08 外部资源（sampled content）

`external_url_dependency`、`missing_relative_resource`、`unsafe_resource_path`、`missing_attachment`、`unsupported_resource_scheme`、`empty_referenced_resource`、`resource_reference_unresolved`。

HTML/Markdown 引用由标准库解析；相对路径只在 delivery root 内词法验证，不解压 archive。HTTP/HTTPS 只表示存在外部依赖，不表示链接失效；本仓库不发起网络请求。`..`、绝对路径、`file:`、`javascript:` 等会保留清理后的相对证据，不输出本机路径。

### ISS-09 溯源（full metadata scan）

`provenance_missing_field`、`provenance_dataset_mismatch`、`provenance_source_file_missing`、`provenance_source_offset_invalid`、`provenance_source_offset_out_of_range`、`provenance_processing_version_missing`、`provenance_version_unsupported`、`canonical_evidence_missing`、`quality_evidence_missing`、`evidence_record_orphan`、`evidence_fingerprint_mismatch`。

审计复算 RecordV1 与 CanonicalDecisionV1 指纹，并对 record/dataset/canonical group 关联做一致性检查。QualityScoreV1 仅作溯源证据，`ACCEPT/REVIEW/REJECT` 不作为本仓库的内容 truth，也不会修改任何上游 evidence。

### 阶段 2 合成证据

`scripts/generate_content_fixtures.py` 用固定 seed 建立 3 个 dataset、article/comment/reply、4 个以上月份、JSONL/TSV RecordV1、本地 HTML/Markdown 引用、singleton/exact/fuzzy canonical 证据和 quality 证据。fixture fingerprint 为 `sha256:42a146c72886844bc8c4190300638165f60843b4a87bc3ec6799b0b8c0e872e9`；正序/逆序创建和重复生成逐字节一致。

valid 包实际为 12 条记录、12 层、0 个 `ISS-05～09` issue，canonical/quality 均 12/12 对账，输出 fingerprint 为 `sha256:adc07357f2db8c5ab8e82ffe561a476c27f9db9530f31cb19537c4ab376c3432`。problem 包实际为 54 条记录、23 层、58 个 issue：`ISS-05=14`、`ISS-06=11`、`ISS-07=10`、`ISS-08=8`、`ISS-09=15`，severity 为 `ERROR=41`、`WARNING=17`；53 条 canonical decision 与 54 条 quality score 被全量对账，输出 fingerprint 为 `sha256:44281f90ce4805f3d57ef6f32cdbbde8c17d57c0d064ff1c7c215d23e30f2c64`。58 条 locator/code/severity/scope 与独立 injection truth 精确一致；各 code 的实际次数保存在 `content-summary.json` 和 truth 中，不容忍 truth 之外的 ERROR/BLOCKER。

## 运行

生成 fixtures：

```bash
python3 scripts/generate_fixtures.py \
  --seed 20260822 \
  --output-dir fixtures/generated
```

Python 共同扫描：

```bash
PYTHONPATH=python/src python3 -m dataset_delivery_audit scan \
  --root fixtures/generated/problem-delivery \
  --output /tmp/delivery-inventory-python.jsonl
```

Rust 共同扫描：

```bash
cargo run --locked --manifest-path rust/Cargo.toml -- scan \
  --root fixtures/generated/problem-delivery \
  --output /tmp/delivery-inventory-rust.jsonl
```

Python 完整阶段 1 审计：

```bash
PYTHONPATH=python/src python3 -m dataset_delivery_audit audit \
  --root fixtures/generated/problem-delivery \
  --expectation fixtures/generated/problem-expectation.json \
  --config configs/audit-v1.json \
  --output-dir /tmp/delivery-audit-python
```

输出固定为 `file-inventory.jsonl`、`issues.jsonl`、`audit-summary.json` 和 `run-manifest.json`；不含浮点业务值、时间戳、绝对路径或随机 ID。

Python 阶段 2 内容审计：

```bash
PYTHONPATH=python/src python3 -m dataset_delivery_audit audit-content \
  --root fixtures/content-generated/problem-delivery \
  --expectation fixtures/content-generated/problem-expectation.json \
  --config configs/content-audit-v1.json \
  --sample-plan configs/content-sample-plan-v1.json \
  --canonical-decisions fixtures/content-generated/problem-canonical-decisions.jsonl \
  --quality-scores fixtures/content-generated/problem-quality-scores.jsonl \
  --output-dir /tmp/delivery-content-audit
```

阶段 2 只输出 `record-issues.jsonl`、`sampling-manifest.json`、`content-summary.json` 和 `run-manifest.json`；不包含完整正文、浮点业务值、当前时间、绝对路径或随机 UUID。

完整验证：

```bash
bash scripts/verify.sh
```

完整验证实际包含 Python `28/28`（阶段 1 为 16、阶段 2 为 12）、Rust `8/8`。两种实现继续对阶段 1 valid 11 条和 problem 37 条 inventory 逐字段 parity；阶段 2 真实运行两个 content CLI，并检查 fixed-seed 双次生成、正逆创建、输入顺序无关的 sample、重复输出、58 条 truth、三个上游契约字节一致、evidence 关联、nested Git、缓存和公开内容安全。

## 当前限制

- 所有数据均为程序生成的合成数据，结果不代表真实公司交付质量。
- 扩展名只能提供格式线索；非 UTF-8 不自动猜编码；损坏分类只陈述标准库和 expectation 可复核的证据。
- `ISS-01～09` 已完成工程验证；`ISS-10～12`（统计勾稽、处理程序归因和证据不足）仍未实现。
- 当前不计算加权总体可用率、置信区间或最终 DeliveryReportV1。
- 当前不生成最终 Markdown/CSV 交付报告。
- sampling 只给出确定性覆盖证据，尚未外推成总体问题率；合成 issue 分布也不代表真实交付发生率。
- 当前没有 Git 初始化、commit、tag、GitHub 仓库或上传行为；仓库仍为 `IN_PROGRESS`，不能声称完整或可发布。
