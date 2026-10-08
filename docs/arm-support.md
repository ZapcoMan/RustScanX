# ARM 支持

> 本页属于 **RustScanX**——一个基于原项目 [RustScan](https://github.com/bee-san/RustScan.git)
> 二次开发并向其致敬的分支。

本页介绍 RustScanX 的 CI 会构建和测试哪些 ARM 目标，以及如何自行构建 ARM 二进制文件。

## CI 覆盖范围

| 目标 | 由谁构建 | 由谁测试 |
| --- | --- | --- |
| `aarch64-unknown-linux-gnu`（64 位 ARM Linux） | [build.yml](../.github/workflows/build.yml) 中的 `build-nix` 任务 | [test.yml](../.github/workflows/test.yml) 中的 `Test Suite (ubuntu-24.04-arm)` |
| `armv7-unknown-linux-gnueabihf`（32 位 ARM Linux） | [build.yml](../.github/workflows/build.yml) 中的 `build-nix` 任务 | CI 中未测试 |
| `aarch64-apple-darwin`（Apple Silicon macOS） | [build.yml](../.github/workflows/build.yml) 中的 `build-macos-aarch64` 任务 | [test.yml](../.github/workflows/test.yml) 中的 `Test Suite (macos-latest)` |

- **构建**使用 [`houseabsolute/actions-rust-cross`](https://github.com/houseabsolute/actions-rust-cross)。它在 x86_64 运行器上通过 [`cross`](https://github.com/cross-rs/cross) 交叉编译 Linux ARM 目标。
- **测试**在 GitHub 托管的 arm64 运行器上原生运行：Linux 用 `ubuntu-24.04-arm`，而 `macos-latest` 运行在 Apple Silicon 上。它们与其他所有平台运行相同的 `just test` 配方。

## 在本地构建 ARM 二进制文件

最简单的选项是 `cross`，它会在一个已经拥有正确工具链和链接器的容器中运行构建。它需要 Docker 或 Podman。

```sh
cargo install cross
cross build --locked --release --target aarch64-unknown-linux-gnu
# 或者，对于 32 位 ARM：
cross build --locked --release --target armv7-unknown-linux-gnueabihf
```

生成的二进制文件位于 `target/<target>/release/rustscanx`。

在 ARM 机器上（例如运行 64 位系统的 Raspberry Pi，或 Apple Silicon Mac）你不需要 `cross`；普通的原生构建即可工作：

```sh
cargo build --locked --release
```

## 故障排查

- **`error[E0463]: can't find crate for std`，或链接器错误：** 你在用普通的 `cargo` 进行交叉编译。要么使用 `cross`，要么安装目标（`rustup target add <target>`）并配备匹配的交叉链接器。
- **`cross` 无法拉取它的镜像：** 检查 Docker 或 Podman 是否正在运行，以及你的用户是否能访问它。
