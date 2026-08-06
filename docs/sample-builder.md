# FreeVRG 样本构建器

`scripts/build_samples.py` 将 `data/dataset/dataset_index.json` 中的漏洞索引记录转换为
Agent 主链路需要的结构化样本。

## 输入

- dataset record：`sa_id`、`cve`、`module`、`affects`、`git_hashes`、
  `github_commit_urls`、`advisory_raw_url`
- FreeBSD src Git 仓库：用于读取 fix commit、`commit^` 和 `commit` 的源码快照
- advisory raw URL：用于补充 `advisory_text`，离线模式下可为空

## 输出

每条可处理记录写出一个 `data/samples/<sa-id>.json`，核心字段包括：

- `advisory_text`
- `diff`
- `files_changed`
- `before_code`
- `after_code`
- `context.target_functions`

这些字段可直接供 `PatternAgent`、`RuleAgent` 和 `HarnessAgent` 使用。多 CVE SA 需要先经过
`MultiCveAgent` 拆分为单 CVE child sample，再进入主链路。

## 使用

先构建漏洞索引：

```bash
pdm run python scripts/build_dataset.py \
  --output-dir data/dataset \
  --snapshot-date 2026-06-21
```

再从索引生成样本：

```bash
pdm run python scripts/build_samples.py \
  --dataset data/dataset/dataset_index.json \
  --freebsd-src vendor/freebsd-src \
  --output-dir data/samples \
  --sa-id FreeBSD-SA-20:26 \
  --fetch-missing \
  --overwrite
```

如果本地 `vendor/freebsd-src` 已包含目标历史 commit，可以加 `--offline` 避免联网：

```bash
pdm run python scripts/build_samples.py \
  --dataset data/dataset/dataset_index.json \
  --freebsd-src vendor/freebsd-src \
  --output-dir data/samples \
  --sa-id FreeBSD-SA-20:26 \
  --offline \
  --overwrite
```

## 当前策略

基础构建器默认只处理单 CVE、FreeBSD-SA、且有 Git commit 的记录。它会：

1. 从 dataset 选择 fix commit。
2. 用 `git show --find-renames --unified=80` 取得 fix diff。
3. 从 diff hunk header 提取目标函数名。
4. 如果 hunk header 不可靠，则从 before/after 文件中选择函数体发生变化的共同函数。
5. 从 `commit^:<path>` 和 `commit:<path>` 抽取 before/after 函数体。
6. 写出 Agent-ready sample JSON。

该脚本不负责判断漏洞语义，也不负责生成 harness。harness 生成仍由
`scripts/generate_harnesses.py` 和 `HarnessAgent` 完成。

## 多 CVE 拆分

多 CVE SA 不能把同一份综合 diff 无差别复制给每个 CVE 后直接生成正式规则。当前项目增加了
`MultiCveAgent`，用于读取一个已经包含 `advisory_text`、`diff`、`before_code`、`after_code`
的多 CVE sample，并输出多个单 CVE child sample：

```bash
pdm run python scripts/split_multi_cve_sample.py \
  data/samples/多CVE/FreeBSD-SA-XX-YY.json \
  --output-dir data/samples/split \
  --overwrite
```

输出 child sample 会保留：

- `source_sa`：原始 SA 溯源
- `cve`：单 CVE 列表
- `context.multi_cve_split.evidence_mode`：`exact_patch`、`child_commit_exact`、
  `cve_guided_composite` 或 `ambiguous`
- `context.requires_human_review`：非高置信精确证据默认需要人工复核

推荐流程是：多 CVE sample 先拆分，人工确认低置信度 child，再对单 CVE child 运行
`main.py`、`generate_harnesses.py` 和机制级 CodeQL 校验。

## 规则泛化变体

通过主链路生成 pattern 后，可以为同一个 pattern 生成多种 QL rule variant。variant 由两部分组成：

- `scope`：控制扫哪里，支持 `exact`、`component`、`freebsd`、`upstream`
- `semantic`：控制规则描述能力，支持 `syntactic`、`structural`、`dataflow`、`semantic`

示例：

```bash
pdm run python scripts/generate_rule_variants.py \
  data/patterns/freebsd-sa-20-26.md \
  --variant exact:syntactic \
  --variant component:dataflow \
  --variant freebsd:semantic \
  --overwrite
```

默认会生成：

- `exact-syntactic`：用于历史 harness / 回归验证
- `component-dataflow`：用于当前 FreeBSD 对应模块扫描
- `freebsd-semantic`：用于更宽的 FreeBSD 全源码候选发现

每次生成会额外写出 `<pattern>.rule-variants.json` manifest，记录每条变体的 `scope_level`、
`semantic_level` 和输出路径。

## 后续链路

生成 sample 后运行主链路：

```bash
pdm run python main.py data/samples/freebsd-sa-20-26.json
```

如需机制级验证，先生成 harness 和 CodeQL database：

```bash
pdm run python scripts/generate_harnesses.py \
  data/samples/freebsd-sa-20-26.json \
  --output-root data/generated-harnesses \
  --clang-check \
  --cc /usr/bin/clang

CODEQL=/home/wwwcom/.local/bin/codeql CC=/usr/bin/clang \
  scripts/build_harness_databases.sh --root data/generated-harnesses --force
```

然后将 `.env` 的 `VALIDATION_DATABASES_DIR` 指向对应 `db` 目录，再运行主链路或直接调用
`Validator`。
