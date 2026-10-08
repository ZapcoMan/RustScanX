//! 脚本引擎，根据标签（tag）来运行脚本。
//!
//! 本模块用于筛选并运行用户所选的脚本。
//!
//! 新增了一个命令行与配置文件选项。
//!
//! ## `--scripts`
//!
//! ### `default`
//!
//! 这是默认行为，与 RustScan 从一开始就有的行为一致。
//!
//! 用户无需为此做任何选择。这是唯一内嵌在 RustScan 中、默认运行的脚本。
//!
//! ### `none`
//!
//! 用户必须使用 `--scripts none` 命令行参数，或在配置文件里写 `scripts =
//! "none"`。
//!
//! 不会运行任何脚本，这取代已被移除的 `--no-nmap` 选项。
//!
//! ### `custom`
//!
//! 用户必须使用 `--scripts custom` 命令行参数，或在配置文件里写
//! `scripts = "custom"`。
//!
//! RustScan 会在用户的主目录下查找脚本配置文件：
//! `home_dir/.rustscan_scripts.toml`
//!
//! 配置文件有 3 个可选字段：`tag`、`developer` 和 `port`。在后续流程中只会
//! 用到 `tag` 字段。
//!
//! RustScan 还会在用户的主目录下查找可用的脚本：
//! `home_dir/.rustscan_scripts`，并尝试读取所有文件，把它们解析成一个
//! [`ScriptFile`] 的 vector。
//!
//! 按标签筛选意味着在 `rustscan_scripts.toml` 文件中找到的标签，也必须出现
//! 在 [`ScriptFile`] 中，否则该脚本不会被选中。
//!
//! 要 [`ScriptFile`] 被选中，`rustscan_script.toml` 中的所有标签至少要全部
//! 存在，但也可以更多。
//!
//! 配置文件示例：
//!
//! - `fixtures/test_rustscan_scripts.toml`
//!
//! 仅含元数据的测试固件（fixture）：
//!
//! - `fixtures/.rustscan_scripts/test_script.txt`
//!
//! 脚本文件中的 `call_format` 有 2 种变体：
//!
//! 一种是所有可能的标签 `{{script}}`、`{{ip}}` 和 `{{port}}` 都在其中。
//!
//! - `{{script}}` 部分会被替换成在解析可用脚本时收集到的脚本文件完整路径。
//! - `{{ip}}` 部分会被替换成我们从扫描中得到的 ip。
//! - `{{port}}` 部分会被替换成以脚本文件中的 `ports_separator` 分隔的端口。
//!
//! 而当格式中只有 `{{ip}}` 和 `{{port}}` 时，就只会把它们替换成扫描带来的
//! 参数。
//!
//! 这使得运行像 `nmap` 这样系统已安装的命令、并给它任意参数变得很容易。
//!
//! 如果格式与此不同，脚本会被静默丢弃且不会运行。借助 `Debug` 选项可以看清
//! 它出错在哪里。

#![allow(clippy::module_name_repetitions)]

use crate::input::ScriptsRequired;
use anyhow::{anyhow, Result};
use log::debug;
use serde_derive::{Deserialize, Serialize};
use std::fs::{self, File};
use std::io::{self, prelude::*};
use std::net::IpAddr;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::string::ToString;
use text_placeholder::Template;

#[cfg(unix)]
use std::os::unix::process::ExitStatusExt;

static DEFAULT: &str = r#"tags = ["core_approved", "RustScan", "default"]
developer = [ "RustScan", "https://github.com/RustScan" ]
ports_separator = ","
call_format = "nmap -vvv -p {{port}} -{{ipversion}} {{ip}}"
"#;

#[cfg(not(tarpaulin_include))]
pub fn init_scripts(scripts: &ScriptsRequired) -> Result<Vec<ScriptFile>> {
    let mut scripts_to_run: Vec<ScriptFile> = Vec::new();

    match scripts {
        ScriptsRequired::None => {}
        ScriptsRequired::Default => {
            let default_script =
                toml::from_str::<ScriptFile>(DEFAULT).expect("Failed to parse Script file.");
            scripts_to_run.push(default_script);
        }
        ScriptsRequired::Custom => {
            let script_config = ScriptConfig::read_config()?;
            debug!("Script config \n{script_config:?}");

            let script_dir_base = if let Some(config_directory) = &script_config.directory {
                PathBuf::from(config_directory)
            } else {
                dirs::home_dir().ok_or_else(|| anyhow!("Could not infer scripts path."))?
            };

            let script_paths = find_scripts(script_dir_base)?;
            debug!("Scripts paths \n{script_paths:?}");

            let parsed_scripts = parse_scripts(script_paths);
            debug!("Scripts parsed \n{parsed_scripts:?}");

            // 只有包含 ScriptConfig 中所有标签的脚本才会被选中。
            if let Some(config_hashset) = script_config.tags {
                for script in parsed_scripts {
                    if let Some(script_hashset) = &script.tags {
                        if script_hashset
                            .iter()
                            .all(|tag| config_hashset.contains(tag))
                        {
                            scripts_to_run.push(script);
                        } else {
                            debug!(
                                "\nScript tags does not match config tags {:?} {}",
                                script_hashset,
                                script.path.unwrap().display()
                            );
                        }
                    }
                }
            }
            debug!("\nScript(s) to run {scripts_to_run:?}");
        }
    }

    Ok(scripts_to_run)
}

pub fn parse_scripts(scripts: Vec<PathBuf>) -> Vec<ScriptFile> {
    let mut parsed_scripts: Vec<ScriptFile> = Vec::with_capacity(scripts.len());
    for script in scripts {
        debug!("Parsing script {}", script.display());
        if let Some(script_file) = ScriptFile::new(script) {
            parsed_scripts.push(script_file);
        }
    }
    parsed_scripts
}

#[derive(Clone, Debug)]
#[allow(dead_code)]
pub struct Script {
    // 脚本自身的路径。
    path: Option<PathBuf>,

    // 从扫描器得到的 Ip。
    ip: IpAddr,

    // 端口扫描发现的开放端口。
    open_ports: Vec<u16>,

    // 在 ScriptFile 中发现的端口；若定义了它，则只会把它与 ip 一起用于运行。
    trigger_port: Option<String>,

    // 当我们想用这些端口的字符串格式（例如 nmap -p）时，用于拼接端口的分隔字符。
    ports_separator: Option<String>,

    // 在 ScriptFile 中发现的标签。
    tags: Option<Vec<String>>,

    // 我们希望脚本运行所用的格式。
    call_format: Option<String>,
}

#[derive(Serialize)]
struct ExecPartsScript {
    script: String,
    ip: String,
    port: String,
    ipversion: String,
}

#[derive(Serialize)]
struct ExecParts {
    ip: String,
    port: String,
    ipversion: String,
}

impl Script {
    pub fn build(
        path: Option<PathBuf>,
        ip: IpAddr,
        open_ports: Vec<u16>,
        trigger_port: Option<String>,
        ports_separator: Option<String>,
        tags: Option<Vec<String>>,
        call_format: Option<String>,
    ) -> Self {
        Self {
            path,
            ip,
            open_ports,
            trigger_port,
            ports_separator,
            tags,
            call_format,
        }
    }

    // 某些变量在读取前会被修改，而编译器会对 warn(unused_assignments) 报警告
    #[allow(unused_assignments)]
    pub fn run(self) -> Result<String> {
        debug!("run self {:?}", self);

        let separator = self.ports_separator.unwrap_or_else(|| ",".into());

        let mut ports_str = self
            .open_ports
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<String>>()
            .join(&separator);
        if let Some(port) = self.trigger_port {
            ports_str = port;
        }

        let mut final_call_format = String::new();
        if let Some(call_format) = self.call_format {
            final_call_format = call_format;
        } else {
            return Err(anyhow!("Failed to parse execution format."));
        }
        let default_template: Template = Template::new(&final_call_format);
        let mut to_run = String::new();

        if final_call_format.contains("{{script}}") {
            let exec_parts_script: ExecPartsScript = ExecPartsScript {
                script: self.path.unwrap().to_str().unwrap().to_string(),
                ip: self.ip.to_string(),
                port: ports_str,
                ipversion: match &self.ip {
                    IpAddr::V4(_) => String::from("4"),
                    IpAddr::V6(_) => String::from("6"),
                },
            };
            to_run = default_template.fill_with_struct(&exec_parts_script)?;
        } else {
            let exec_parts: ExecParts = ExecParts {
                ip: self.ip.to_string(),
                port: ports_str,
                ipversion: match &self.ip {
                    IpAddr::V4(_) => String::from("4"),
                    IpAddr::V6(_) => String::from("6"),
                },
            };
            to_run = default_template.fill_with_struct(&exec_parts)?;
        }
        debug!("\nScript format to run {to_run}");
        execute_script(&to_run)
    }
}

#[cfg(not(tarpaulin_include))]
fn execute_script(script: &str) -> Result<String> {
    debug!("\nScript arguments {script}");

    let (cmd, arg) = if cfg!(unix) {
        ("sh", "-c")
    } else {
        ("cmd.exe", "/c")
    };

    match Command::new(cmd)
        .args([arg, script])
        .stdin(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
    {
        Ok(output) => {
            let status = output.status;

            let es = match status.code() {
                Some(code) => code,
                _ => {
                    #[cfg(unix)]
                    {
                        status.signal().unwrap()
                    }

                    #[cfg(windows)]
                    {
                        return Err(anyhow!("Unknown exit status"));
                    }
                }
            };

            if es != 0 {
                return Err(anyhow!("Exit code = {}", es));
            }
            Ok(String::from_utf8_lossy(&output.stdout).into_owned())
        }
        Err(error) => {
            debug!("Command error {error}",);
            Err(anyhow!(error.to_string()))
        }
    }
}

pub fn find_scripts(path: PathBuf) -> Result<Vec<PathBuf>> {
    if path.is_dir() {
        debug!("Scripts folder found {}", path.display());
        let mut files_vec: Vec<PathBuf> = Vec::new();
        for entry in fs::read_dir(path)? {
            let entry = entry?;
            files_vec.push(entry.path());
        }
        Ok(files_vec)
    } else {
        Err(anyhow!("Can't find scripts folder {}", path.display()))
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct ScriptFile {
    pub path: Option<PathBuf>,
    pub tags: Option<Vec<String>>,
    pub developer: Option<Vec<String>>,
    pub port: Option<String>,
    pub ports_separator: Option<String>,
    pub call_format: Option<String>,
}

impl ScriptFile {
    fn new(script: PathBuf) -> Option<ScriptFile> {
        let real_path = script.clone();
        let mut lines_buf = String::new();
        if let Ok(file) = File::open(script) {
            for mut line in io::BufReader::new(file).lines().skip(1).flatten() {
                if line.starts_with('#') {
                    line.retain(|c| c != '#');
                    line = line.trim().to_string();
                    line.push('\n');
                    lines_buf.push_str(&line);
                } else {
                    break;
                }
            }
        } else {
            debug!("Failed to read file: {}", real_path.display());
            return None;
        }
        debug!("ScriptFile {} lines\n{}", real_path.display(), lines_buf);

        match toml::from_str::<ScriptFile>(&lines_buf) {
            Ok(mut parsed) => {
                debug!("Parsed ScriptFile{} \n{:?}", real_path.display(), parsed);
                parsed.path = Some(real_path);
                // parsed_scripts.push(parsed);
                Some(parsed)
            }
            Err(e) => {
                debug!("Failed to parse ScriptFile headers {e}");
                None
            }
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct ScriptConfig {
    pub tags: Option<Vec<String>>,
    pub ports: Option<Vec<String>>,
    pub developer: Option<Vec<String>>,
    pub directory: Option<String>,
}

#[cfg(not(tarpaulin_include))]
impl ScriptConfig {
    pub fn read_config() -> Result<ScriptConfig> {
        let Some(mut home_dir) = dirs::home_dir() else {
            return Err(anyhow!("Could not infer ScriptConfig path."));
        };
        home_dir.push(".rustscan_scripts.toml");

        let content = fs::read_to_string(home_dir)?;
        let config = toml::from_str::<ScriptConfig>(&content)?;
        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn find_and_parse_scripts() {
        let scripts = find_scripts("fixtures/.rustscan_scripts".into()).unwrap();
        let scripts = parse_scripts(scripts);
        assert_eq!(scripts.len(), 1);
    }

    #[test]
    #[should_panic]
    fn find_invalid_folder() {
        let _scripts = find_scripts("Cargo.toml".into()).unwrap();
    }

    #[test]
    #[should_panic]
    fn open_script_file_invalid_headers() {
        ScriptFile::new("fixtures/.rustscan_scripts/test_script_invalid_headers.txt".into())
            .unwrap();
    }

    #[test]
    #[should_panic]
    fn open_nonexisting_script_file() {
        ScriptFile::new("qwertyuiop.txt".into()).unwrap();
    }

    #[test]
    fn parse_txt_script() {
        let script_f =
            ScriptFile::new("fixtures/.rustscan_scripts/test_script.txt".into()).unwrap();
        assert_eq!(
            script_f.tags,
            Some(vec!["core_approved".to_string(), "example".to_string()])
        );
        assert_eq!(
            script_f.developer,
            Some(vec![
                "example".to_string(),
                "https://example.org".to_string()
            ])
        );
        assert_eq!(script_f.ports_separator, Some(",".to_string()));
        assert_eq!(
            script_f.call_format,
            Some("fixture {{ip}} {{port}}".to_string())
        );
    }

    #[test]
    fn test_custom_directory_config() {
        // 创建测试配置
        let config_str = r#"
            tags = ["core_approved", "example"]
            directory = "fixtures/.rustscan_scripts"
        "#;

        let config: ScriptConfig = toml::from_str(config_str).unwrap();
        assert_eq!(
            config.directory,
            Some("fixtures/.rustscan_scripts".to_string())
        );

        // 测试该目录确实被使用
        let script_dir_base = PathBuf::from(config.directory.unwrap());
        let scripts = find_scripts(script_dir_base).unwrap();

        // 验证我们找到了测试脚本
        assert!(scripts.iter().any(|p| p
            .file_name()
            .and_then(|f| f.to_str())
            .map(|s| s == "test_script.txt")
            .unwrap_or(false)));
    }

    #[test]
    fn test_default_directory_fallback() {
        let config_str = r#"
            tags = ["core_approved", "example"]
        "#;

        let config: ScriptConfig = toml::from_str(config_str).unwrap();
        assert_eq!(config.directory, None);

        // 测试回退到主目录
        let script_dir_base = if let Some(config_directory) = &config.directory {
            PathBuf::from(config_directory)
        } else {
            dirs::home_dir().unwrap()
        };

        assert_eq!(script_dir_base, dirs::home_dir().unwrap());
    }
}
