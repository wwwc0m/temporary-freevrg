# FreeVRG 数据集构建器

这套脚本是对 FreeVRG v1.4 漏洞索引行为的可复现实现，不是对遗失脚本原始代码的恢复。
正常构建不读取参考压缩包；参考包只用于逆向调查和可选的黄金验证。

## 数据来源

- `freebsd/freebsd-doc` 的 `website/static/security/advisories/FreeBSD-SA-*.asc`
- `openssl/openssl`
- `libexpat/libexpat`
- `libarchive/libarchive`
- `openssh/openssh-portable`
- `freebsd/freebsd-src` 的 commit 元数据（新记录的启发式匹配和复核）

Git 仓库缓存在 `--cache-dir/git`。Git 对象库本身就是原始历史缓存；需要 REST commit
候选详情时，请求按 URL 缓存在 `--cache-dir/http`。HTTP 客户端实现了超时、三次重试、
限流状态日志和可选 `GITHUB_TOKEN`，日志不会输出令牌。commit search 与 path commit 列表
按页请求、按完整查询参数逐页缓存，并设置了有限页数的安全上限。

## 构建逻辑

公告解析器从头部读取 Topic、Category、Announced 和 Affects，以文件名后缀作为稳定的
module，并从完整公告提取去重后的 CVE。从 Correction details 提取 Git hash 和 SVN
revision。快照日期之后的公告不会进入结果；ports、外部独立包和 CPU 硬件缓解公告会被
过滤。

上游采集按固定项目顺序遍历快照时点可见的 commit 图，从完整 commit message 提取 CVE，
排除已被 FreeBSD-SA 覆盖的 CVE，并按 CVE 去重。一个 commit 的多个 CVE 会拆为多条记录。
新记录若没有审计结论，会按组件路径、时间窗口、CVE/版本消息和 changed paths 在
`freebsd-src` 中评分匹配；纯文档、man page、release note、UPDATING 或版本号噪声不会被
接受为代码修复。

scope 的自动判定优先看修改路径：`sys/` 为 kernel，库产物路径为 lib，用户态命令和守护
进程为 tool。路径不可得时使用审计过的 module fallback。`is_priority` 严格等价于 scope
为 lib 或 tool。质量规则为：CVE 和可信 commit 均有是 Q3，只有一个是 Q2，均无是 Q1。
新记录能取得文件列表时会生成初始 `commit_grade`；纯文档为 `noise_only`，人工 grade 与
scope 始终最后应用。

## 人工审计配置

[`scripts/dataset_builder/curation_v1_4.json`](../scripts/dataset_builder/curation_v1_4.json)
只保存字段级例外和人工审计结论，不保存 368 条完整记录。它包括：

- SVN 到 Git 的确认、失败和错误 hash 清除；
- 上游组件在 FreeBSD 中的集成 commit 审计；
- 少量 scope、dual-scope note 和来源 commit 修正；
- OpenSSH 历史中的错误 CVE 归属排除；
- v1.4 的 177 项人工 `commit_grade`；
- 每项结论的简短 reason。

因此，公告头部和上游 commit 元数据仍然来自官方仓库；配置只固定无法稳定自动推导、或已
经人工复核的字段。

## 使用

安装锁定依赖并在线构建：

```bash
pdm install
pdm run python scripts/build_dataset.py \
  --output-dir data/dataset \
  --snapshot-date 2026-06-21
```

首次在线构建成功后，可以仅用缓存重建：

```bash
pdm run python scripts/build_dataset.py \
  --output-dir data/dataset \
  --snapshot-date 2026-06-21 \
  --offline
```

`--offline` 不执行任何 fetch 或 HTTP 请求。普通在线模式每次都会更新远端 ref；`--refresh`
额外强制刷新 Git ref 与 HTTP 页缓存。缓存仓库会写入 `.freevrg-cache.json`，记录仓库、分支、
抓取时间、最早可用 commit 日期和最新远端 commit。若较新的浅缓存无法覆盖所需旧快照，在线
模式会自动 unshallow，离线模式会给出带 `--refresh` 操作提示的错误。

强制刷新官方仓库和 HTTP 缓存：

```bash
pdm run python scripts/build_dataset.py --refresh --snapshot-date 2026-06-21
```

令牌环境变量默认为 `GITHUB_TOKEN`，也可通过 `--github-token-env` 指定其他变量名。

## 黄金验证

验证器按压缩包条目名称定位且只安全读取三个目标文件，不依赖压缩包中文根目录名称。JSON 和 CSV 会逐条、
逐字段比较；XLSX 会比较 Sheet 名称、尺寸、单元格值、冻结窗格、筛选，并确认 commit 单元格
具有真实 hyperlink。发生差异时会打印第一个不同记录和字段。

```bash
pdm run python scripts/build_dataset.py \
  --output-dir data/dataset \
  --snapshot-date 2026-06-21 \
  --reference-zip /path/to/数据构建.zip \
  --validate-reference
```

v1.4 固定统计为 368 条：236 条 FreeBSD-SA、132 条 upstream、234 条 priority、133 条
kernel、Q3/Q2/Q1 分别为 300/65/3，Q3 且 lib/tool 为 177 条。

## 限制

- 空缓存的首次运行需要访问公共 GitHub Git 服务，下载时间取决于网络质量。
- 对 v1.4 之后的新 SVN 公告或新上游 CVE，启发式匹配仍应人工复核后再升级为 Q3。
- 未配置令牌时 GitHub REST API 使用匿名限额；限流响应会给出 URL、状态和 reset 信息。
- v1.4 的 `commit_grade` 继续采用 177 项人工审计；快照之后的新记录才在无人工结论时使用
  changed paths 生成初判。
