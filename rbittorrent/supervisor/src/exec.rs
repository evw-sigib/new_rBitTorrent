//! Runs the few external tools the supervisor needs (`ip`, `wg`, `nft`).
//!
//! Secrets are only ever passed on stdin, never as arguments, so they cannot
//! show up in `ps` output or `/proc/<pid>/cmdline`.

use std::future::Future;
use std::process::Stdio;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use tokio::io::AsyncWriteExt;

use crate::process;

/// Upper bound for any single helper command.
const COMMAND_TIMEOUT: Duration = Duration::from_secs(20);

/// Output of a successful command.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Output {
    pub stdout: String,
    pub stderr: String,
}

/// Something that can run a program. Abstracted so the WireGuard, routing and
/// firewall sequences can be unit-tested without root.
pub trait Runner: Send + Sync {
    /// Runs `program args...`, feeding `stdin` if given. Fails on a non-zero exit.
    fn run(
        &self,
        program: &str,
        args: &[&str],
        stdin: Option<&[u8]>,
    ) -> impl Future<Output = Result<Output>> + Send;
}

/// The real runner.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemRunner;

impl Runner for SystemRunner {
    async fn run(&self, program: &str, args: &[&str], stdin: Option<&[u8]>) -> Result<Output> {
        let display = format!("{program} {}", args.join(" "));
        let mut cmd = tokio::process::Command::new(program);
        cmd.args(args)
            .stdin(if stdin.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);

        let mut child = process::spawn_tracked(&mut cmd)
            .with_context(|| format!("cannot start `{program}` (is it installed?)"))?;

        if let Some(data) = stdin {
            let mut pipe = child
                .inner_mut()
                .stdin
                .take()
                .context("child stdin pipe missing")?;
            pipe.write_all(data)
                .await
                .with_context(|| format!("cannot write to stdin of `{program}`"))?;
            pipe.shutdown().await.ok();
            drop(pipe);
        }

        let out = tokio::time::timeout(COMMAND_TIMEOUT, child.wait_with_output())
            .await
            .with_context(|| format!("`{display}` timed out after {COMMAND_TIMEOUT:?}"))?
            .with_context(|| format!("waiting for `{display}` failed"))?;

        let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&out.stderr).trim().to_owned();
        if !out.status.success() {
            bail!("`{display}` failed ({}): {stderr}", out.status);
        }
        Ok(Output { stdout, stderr })
    }
}

#[cfg(test)]
pub mod fake {
    //! A recording runner for tests.

    use super::*;
    use std::collections::VecDeque;
    use std::sync::Mutex;

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct Call {
        pub program: String,
        pub args: Vec<String>,
        pub stdin: Option<String>,
    }

    impl Call {
        pub fn line(&self) -> String {
            format!("{} {}", self.program, self.args.join(" "))
        }
    }

    /// Records every call; answers from a queue of `(prefix, stdout)` scripted
    /// responses (first match wins), `Err` for prefixes in `fail`.
    #[derive(Debug, Default)]
    pub struct FakeRunner {
        pub calls: Mutex<Vec<Call>>,
        pub responses: Mutex<VecDeque<(String, String)>>,
        pub fail: Mutex<Vec<String>>,
    }

    impl FakeRunner {
        pub fn respond(&self, prefix: &str, stdout: &str) {
            self.responses
                .lock()
                .unwrap()
                .push_back((prefix.to_owned(), stdout.to_owned()));
        }

        pub fn fail_on(&self, prefix: &str) {
            self.fail.lock().unwrap().push(prefix.to_owned());
        }

        pub fn calls(&self) -> Vec<Call> {
            self.calls.lock().unwrap().clone()
        }

        pub fn lines(&self) -> Vec<String> {
            self.calls().iter().map(Call::line).collect()
        }
    }

    impl Runner for FakeRunner {
        async fn run(&self, program: &str, args: &[&str], stdin: Option<&[u8]>) -> Result<Output> {
            let call = Call {
                program: program.to_owned(),
                args: args.iter().map(|s| (*s).to_owned()).collect(),
                stdin: stdin.map(|s| String::from_utf8_lossy(s).into_owned()),
            };
            let line = call.line();
            self.calls.lock().unwrap().push(call);
            if self
                .fail
                .lock()
                .unwrap()
                .iter()
                .any(|p| line.starts_with(p))
            {
                bail!("`{line}` failed (scripted)");
            }
            let mut responses = self.responses.lock().unwrap();
            if let Some(pos) = responses
                .iter()
                .position(|(p, _)| line.starts_with(p.as_str()))
            {
                let (_, stdout) = responses.remove(pos).unwrap_or_default();
                return Ok(Output {
                    stdout,
                    stderr: String::new(),
                });
            }
            Ok(Output::default())
        }
    }
}
