# simple-file-encrypt

[English](README.md)

`simple-file-encrypt` 用单一密码就地加解密本地文件，密文对 git 友好：文本文件**逐行、确定性**加密，密文可以按行 diff 与合并，内容不变则重新加密得到逐字节相同的输出。工具本身从不调用 git。

## ⚠️ 托付数据之前请先读这一节

git 友好性是用明确的机密性代价换来的：

- 密文暴露**精确的行数、每一行的精确字节长度**，以及任意两个版本之间到底哪些行变了。
- 同一文件内（以及该文件的 git 历史、分支、克隆之间，同一密钥纪元内）**相同的明文行产生相同的密文行**。高频短行（`}`、空行、样板代码）仅靠频率分析就能大致识别；知道某个历史版本明文的人，等于拿到了该路径所有版本通用的密文→明文字典。
- 确定性加密只保护**不可预测**的内容：随机 token 和密钥是安全的；可猜测的配置行可以被验证猜测——但只能借助已知明文字典（该文件任一已提交版本的明文）或同路径的加密 oracle，仅凭密文本身无法完成。
- 文本模式只有**单元级完整性**：拥有写权限的攻击者可以不被察觉地重排、删除、复制或复活真实的密文行——这是按行合并的代价，请靠审查 git 历史来兜底。

如果你需要隐藏文件结构与修改模式，请改用 `age`/`git-crypt` 一类工具。完整分析见
[docs/threat-model.md](docs/threat-model.md)，请务必阅读。

## 工作原理

- 一个密码（经 Argon2id）包裹随机的 32 字节**域密钥**（AES-CMAC-SIV 密钥包裹），存放在随仓库提交的配置文件 `.simple-file-encrypt.toml` 中。没有该配置文件密文就无法解密——两者必须放在同一仓库里。
- 每个单元（文本行、空文件标记、64 KiB 二进制分块）都用 **AES-CMAC-SIV（RFC 5297，AES-256）** 加密，密钥由 BLAKE3 从域密钥和文件的仓库相对路径派生。没有 nonce、加密时没有随机性：密文是 `(域密钥, 路径, 模式, 内容)` 的纯函数。
- 含 NUL 字节的文件（或被 `force_binary` 匹配的路径）走二进制模式：分块加密，外加能检测跨版本拼接的全文件 tag。
- `passwd` 只重新包裹密钥环、不动密文——但**不能撤销**旧密码（git 历史里留着旧的包裹密钥环）。密码泄露的应对是先 `passwd` **再 `rekey`**：铸造新域密钥并在内存中迁移所有文件。

## 安装

已有 Rust 工具链（1.89 及以上）时：

```console
$ cargo install simple-file-encrypt
```

也可从 [GitHub Releases](https://github.com/orzogc/simple-file-encrypt/releases)
下载预构建包：静态链接的 Linux 二进制（x86_64/aarch64，musl，任何发行版可直接运行）
与 macOS（Apple silicon），均附带 SHA-256 校验和与 keyless（Sigstore）构建来源证明，
可用 `gh attestation verify <archive> --repo orzogc/simple-file-encrypt` 验证。

## 快速上手

```console
$ cd your-repo
$ simple-file-encrypt init                 # 每仓库一次；提示输入密码
$ simple-file-encrypt add .env secrets/
$ simple-file-encrypt e                    # 加密所有托管文件
$ git add -A && git commit
$ simple-file-encrypt d                    # 本地在明文上工作
$ simple-file-encrypt e                    # 提交前重新加密
```

在 `.gitattributes` 中给托管路径标记 `-text`，防止 git 转换行尾（文本密文是字节精确、LF 定界的）：

```gitattributes
.env            -text
secrets/**      -text
```

## 命令

| 命令 | 作用 |
|---|---|
| `init` | 在当前目录创建 `.simple-file-encrypt.toml` |
| `encrypt`（`e`）`[PATHS…]` | 就地加密托管或指定的文件（自动纳入托管清单） |
| `decrypt`（`d`）`[PATHS…]` | 就地解密托管或指定的文件 |
| `add` / `remove <PATHS…>` | 维护托管清单（无需密码） |
| `add --exclude` / `remove --exclude <PATHS…>` | 维护排除清单：被排除的路径即使位于托管目录下也不会被加密 |
| `status` | 报告每个托管文件的状态（无需密码） |
| `check [PATHS…]` | CI 闸门：全部探测为已加密才退出 0（无需密码） |
| `verify [PATHS…]` | 在内存中完整认证密文；`check && verify` 是完整闸门 |
| `passwd`（`p`） | 修改密码（仅重新包裹；**不是**撤销） |
| `rekey [--continue] [--prune]` | 轮换域密钥并迁移密文 |

命令细节、锁、失败语义与 git 集成配方（检查**暂存区**的 pre-commit 钩子）见 [docs/cli.md](docs/cli.md)。

## 文档

| 文档 | 内容 |
|---|---|
| [docs/design.md](docs/design.md) | 设计总览与取舍 |
| [docs/crypto.md](docs/crypto.md) | 密钥层级、AES-SIV 用法、KDF 分级 |
| [docs/format.md](docs/format.md) | 规范性文件格式 |
| [docs/cli.md](docs/cli.md) | 命令语义 |
| [docs/threat-model.md](docs/threat-model.md) | 保护什么、不保护什么 |

## 实际限制

- 文件整体载入内存处理：单文件上限 256 MiB，文本文件上限 2²² 行。重命名托管文件需先解密（密钥绑定路径）。拒绝处理硬链接文件。仅支持 Linux 与 macOS。
- 诚实声明：本设计由标准化且经过充分分析的组件（RFC 5297 AES-CMAC-SIV、BLAKE3、Argon2id）以直接的方式组合而成，但组合整体未经过独立的密码学审查。

## 许可证

MIT
