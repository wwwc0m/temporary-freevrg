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

这些字段可直接供 `PatternAgent`、`RuleAgent` 和 `HarnessAgent` 使用。

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

第一版只处理单 CVE、FreeBSD-SA、且有 Git commit 的记录。它会：

1. 从 dataset 选择 fix commit。
2. 用 `git show --find-renames --unified=80` 取得 fix diff。
3. 从 diff hunk header 提取目标函数名。
4. 如果 hunk header 不可靠，则从 before/after 文件中选择函数体发生变化的共同函数。
5. 从 `commit^:<path>` 和 `commit:<path>` 抽取 before/after 函数体。
6. 写出 Agent-ready sample JSON。

该脚本不负责判断漏洞语义，也不负责生成 harness。harness 生成仍由
`scripts/generate_harnesses.py` 和 `HarnessAgent` 完成。

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

