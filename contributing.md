你好呀，太空奶牛人 🤠🌌

> **关于 RustScanX**：本项目是基于原开源项目 [RustScan](https://github.com/bee-san/RustScan.git)
> 二次开发而来的分支，并向原项目及其贡献者致敬。下文中涉及上游 issue 标签、
> Wiki 与仓库链接的部分，均指向**原项目**。

RustScanX 一直在寻找贡献者。无论是拼写错误还是重大改动，我们都**需要**并欢迎你的帮助。

在贡献之前，请先阅读我们的[行为准则](https://github.com/RustScan/RustScan/blob/master/CODE_OF_CONDUCT.md)。

简单说（TL;DR）：如果你欺负我们社区的成员，你将被**永久封禁**，没有解禁的机会，也不会任何警告。🤗

RustScan 有 2 个你应该关注的 GitHub issue 主要标签：

- Good First issue（新手友好 issue）
  这些是为开源新手准备的 issue！
  [https://github.com/RustScan/RustScan/issues?q=is%3Aopen+is%3Aissue+label%3A%22good+first+issue%22](https://github.com/RustScan/RustScan/issues?q=is%3Aopen+is%3Aissue+label%3A%22good+first+issue%22)
- Help wanted（寻求帮助）
  这些 issue 并不是专门为新手准备的，但我们仍然需要帮助！
  [https://github.com/RustScan/RustScan/issues?q=is%3Aopen+is%3Aissue+label%3A%22good+first+issue%22+label%3A%22help+wanted%22](https://github.com/RustScan/RustScan/issues?q=is%3Aopen+is%3Aissue+label%3A%22good+first+issue%22+label%3A%22help+wanted%22)

如果你愿意，可以解决这个 issue，或在 issue 下评论寻求帮助。

为开源软件贡献的流程是：

- Fork 仓库
- 做出修改
- 向仓库提交 pull request

然后在对应的 issue 下评论说明你已经完成。

RustScanX 的代码里还有一些 `// TODO`，这些更多是为核心团队准备的，但如果有人愿意帮忙处理这些 issue，我们也不会拒绝。

如果你有任何功能建议或发现 bug，请留下一个 GitHub issue。我们欢迎一切支持 :D

## 感谢你

我无法向你支付报酬 :-( 但我可以把你的 GitHub 主页放在 README 的 `#Contributors` 部分，以表达感谢！:)

## 搭建开发环境

为了让向 RustScanX 贡献更轻松，你可以使用 `contributing.Dockerfile` 来构建一个已经可以编译和试玩 RustScanX 的 Docker 镜像。
要构建它，你只需要运行：

```bash
you@home:~/RustScan$ docker build -t rustscan_contributing -f contributing.Dockerfile
```

然后你需要以一个带数据卷的容器运行，以便它能在_读写权限_下访问 RustScan 文件：

```bash
you@home:~/RustScan$ docker run -ti --rm -v "$PWD":/rustscan -w /rustscan rustscan_contributing bash
```

现在你可以用你最喜欢的编辑器修改 RustScan 文件，一旦你想编译并测试你的修改，在容器提示符中输入以下内容：

```bash
root@container:/rustscan# cargo build
```

你可以在不启动扫描的情况下检查命令行界面：

```bash
root@container:/rustscan# cargo run -- --help
```

你也可以通过以下命令格式化、用 `clippy` 检查代码并进行测试：

```bash
root@container:/rustscan# cargo fmt
root@container:/rustscan# cargo clippy
root@container:/rustscan# cargo test
```

自动化测试和基准测试必须在无网络流量、无外部脚本执行的情况下运行。请保持测试重点在于解析、配置、端口排序、套接字地址迭代和计时辅助函数。不要添加会运行 TCP/UDP 扫描（包括 localhost）、解析主机名，或启动 Nmap 及其他脚本的测试。

扫描行为和速度通过可选启用的 "Scan benchmark" GitHub Actions 工作流（`.github/workflows/scan-benchmark.yml`）单独衡量。它会在触及扫描器、其运行时或其依赖的 pull request 上运行，也可以从 Actions 标签页手动启动。它会以 release 模式构建改动及其基准版本，扫描在运行器内部于 127.0.0.1 上开启的监听端，检查两个构建是否找到相同数量的开放端口，并在任务摘要中添加一个对比表。它的脚本（`.github/scan-benchmark/scan_bench.py`）会扫描回环接口，因此仅适用于一次性使用的 CI 运行器。
