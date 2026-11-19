//! Landlock filesystem sandbox for the children (rtbit and the Ingress
//! proxy).
//!
//! rtbit runs as uid 0 with `CAP_DAC_OVERRIDE` so it can manage files other
//! apps wrote to shared storage, which also means file modes alone cannot
//! keep it away from `/config/wg0.conf`, `/data/options.json` or
//! `/app_configs`. Landlock restricts the paths themselves: the ruleset is
//! built here in the supervisor (allocation and `open` are fine) and applied
//! in the forked child right before `execve` with one async-signal-safe
//! syscall, after `no_new_privs` is set.
//!
//! Kernels without Landlock (or a seccomp profile that blocks it) stop the
//! app before any child starts, unless the user set `allow_unsandboxed`
//! (`process::check_fs_sandbox`). ABI 1 is not used: it
//! denies every cross-folder rename, which would break moving finished
//! downloads.

use std::ffi::CString;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

const CREATE_RULESET_VERSION: u32 = 1 << 0;
const RULE_PATH_BENEATH: libc::c_int = 1;

pub const EXECUTE: u64 = 1 << 0;
pub const WRITE_FILE: u64 = 1 << 1;
pub const READ_FILE: u64 = 1 << 2;
pub const READ_DIR: u64 = 1 << 3;
pub const REMOVE_DIR: u64 = 1 << 4;
pub const REMOVE_FILE: u64 = 1 << 5;
pub const MAKE_CHAR: u64 = 1 << 6;
pub const MAKE_DIR: u64 = 1 << 7;
pub const MAKE_REG: u64 = 1 << 8;
pub const MAKE_SOCK: u64 = 1 << 9;
pub const MAKE_FIFO: u64 = 1 << 10;
pub const MAKE_BLOCK: u64 = 1 << 11;
pub const MAKE_SYM: u64 = 1 << 12;
/// ABI 2: link or rename a file into another folder.
pub const REFER: u64 = 1 << 13;
/// ABI 3: truncate.
pub const TRUNCATE: u64 = 1 << 14;

/// Rights that apply to a file (the others only make sense on folders).
const FILE_RIGHTS: u64 = EXECUTE | WRITE_FILE | READ_FILE | TRUNCATE;
const READ: u64 = READ_FILE | READ_DIR;
const READ_EXEC: u64 = READ | EXECUTE;
const READ_WRITE: u64 = READ
    | WRITE_FILE
    | REMOVE_DIR
    | REMOVE_FILE
    | MAKE_DIR
    | MAKE_REG
    | MAKE_SOCK
    | MAKE_FIFO
    | MAKE_SYM
    | REFER
    | TRUNCATE;

/// Which paths a child may use; everything else is out of reach.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FsPolicy {
    /// Read and execute (system folders, the child's own binary).
    pub read_exec: Vec<PathBuf>,
    /// Read only.
    pub read_only: Vec<PathBuf>,
    /// Read and write (downloads, the child's own state).
    pub read_write: Vec<PathBuf>,
}

impl FsPolicy {
    /// One line for the log.
    pub fn describe(&self) -> String {
        let list = |v: &[PathBuf]| {
            v.iter()
                .map(|p| p.display().to_string())
                .collect::<Vec<_>>()
                .join(", ")
        };
        format!(
            "read-write: {}; read-only: {}",
            if self.read_write.is_empty() {
                "nothing".to_owned()
            } else {
                list(&self.read_write)
            },
            list(&self.read_only)
        )
    }
}

/// A built ruleset, applied in the child with [`Ruleset::restrict_self`].
#[derive(Debug)]
pub struct Ruleset {
    fd: OwnedFd,
    pub abi: i32,
}

#[repr(C)]
struct RulesetAttr {
    handled_access_fs: u64,
}

#[repr(C, packed)]
struct PathBeneathAttr {
    allowed_access: u64,
    parent_fd: i32,
}

/// The kernel's Landlock ABI version, or why it is not usable.
pub fn abi() -> Result<i32, String> {
    // SAFETY: the version query takes no attribute pointer.
    let v = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            std::ptr::null::<RulesetAttr>(),
            0usize,
            CREATE_RULESET_VERSION,
        )
    };
    if v < 0 {
        let e = io::Error::last_os_error();
        return Err(match e.raw_os_error() {
            Some(libc::ENOSYS) => "the kernel has no Landlock support".to_owned(),
            Some(libc::EOPNOTSUPP) => "Landlock is disabled in this kernel".to_owned(),
            Some(libc::EPERM) => "Landlock is blocked (seccomp profile)".to_owned(),
            _ => format!("Landlock is unavailable: {e}"),
        });
    }
    i32::try_from(v).map_err(|_| "unexpected Landlock ABI".to_owned())
}

/// Builds the ruleset for `policy`. Paths that do not exist are skipped.
pub fn build(policy: &FsPolicy) -> Result<Ruleset, String> {
    let abi = abi()?;
    if abi < 2 {
        return Err(format!(
            "Landlock ABI {abi} cannot allow moving files between folders"
        ));
    }
    // Every ABI 1 right (bits 0-12), plus REFER.
    let mut handled = ((1u64 << 13) - 1) | REFER;
    if abi >= 3 {
        handled |= TRUNCATE;
    }
    let attr = RulesetAttr {
        handled_access_fs: handled,
    };
    // SAFETY: a valid attribute struct and its size.
    let fd = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            &attr as *const RulesetAttr,
            std::mem::size_of::<RulesetAttr>(),
            0u32,
        )
    };
    let fd = libc::c_int::try_from(fd)
        .ok()
        .filter(|fd| *fd >= 0)
        .ok_or_else(|| {
            format!(
                "cannot create a Landlock ruleset: {}",
                io::Error::last_os_error()
            )
        })?;
    // SAFETY: the kernel just returned this descriptor (O_CLOEXEC) to us.
    let ruleset = Ruleset {
        fd: unsafe { OwnedFd::from_raw_fd(fd) },
        abi,
    };
    for (paths, access) in [
        (&policy.read_exec, READ_EXEC),
        (&policy.read_only, READ),
        (&policy.read_write, READ_WRITE),
    ] {
        for p in paths {
            ruleset.allow(p, access & handled)?;
        }
    }
    Ok(ruleset)
}

impl Ruleset {
    fn allow(&self, path: &Path, access: u64) -> Result<(), String> {
        let Ok(c) = CString::new(path.as_os_str().as_bytes()) else {
            return Err(format!("{} is not a valid path", path.display()));
        };
        // SAFETY: a NUL-terminated path; O_PATH opens nothing for I/O.
        let raw = unsafe { libc::open(c.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
        if raw < 0 {
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::NotFound {
                return Ok(());
            }
            return Err(format!("cannot open {}: {e}", path.display()));
        }
        // SAFETY: we own the descriptor `open` returned.
        let parent = unsafe { OwnedFd::from_raw_fd(raw) };
        let is_dir = std::fs::metadata(path).is_ok_and(|m| m.is_dir());
        let attr = PathBeneathAttr {
            allowed_access: if is_dir { access } else { access & FILE_RIGHTS },
            parent_fd: parent.as_raw_fd(),
        };
        // SAFETY: a valid rule attribute for RULE_PATH_BENEATH.
        let rc = unsafe {
            libc::syscall(
                libc::SYS_landlock_add_rule,
                self.fd.as_raw_fd(),
                RULE_PATH_BENEATH,
                &attr as *const PathBeneathAttr,
                0u32,
            )
        };
        if rc != 0 {
            return Err(format!(
                "cannot allow {}: {}",
                path.display(),
                io::Error::last_os_error()
            ));
        }
        Ok(())
    }

    /// Applies the ruleset to the calling process. Runs in the forked child
    /// before `execve` (after `no_new_privs`): one syscall, no allocation.
    pub fn restrict_self(&self) -> io::Result<()> {
        // SAFETY: plain syscall with an fd and a zero flag.
        let rc =
            unsafe { libc::syscall(libc::SYS_landlock_restrict_self, self.fd.as_raw_fd(), 0u32) };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

/// The system folders every child needs to start: read and execute.
pub fn system_read_exec() -> Vec<PathBuf> {
    ["/usr", "/lib", "/bin", "/sbin"]
        .into_iter()
        .map(PathBuf::from)
        .collect()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use std::os::unix::process::CommandExt;
    use std::sync::Arc;

    #[test]
    fn a_sandboxed_child_reaches_only_what_the_policy_allows() {
        if let Err(why) = abi() {
            eprintln!("skipping: {why}");
            return;
        }
        let base = std::env::temp_dir().join(format!("rbt-landlock-{}", std::process::id()));
        let allowed = base.join("downloads");
        let secret = base.join("config");
        std::fs::create_dir_all(&allowed).unwrap();
        std::fs::create_dir_all(&secret).unwrap();
        std::fs::write(secret.join("wg0.conf"), "PrivateKey = x").unwrap();
        std::fs::write(allowed.join("a.txt"), "data").unwrap();

        let mut read_only = vec![PathBuf::from("/etc"), PathBuf::from("/proc")];
        read_only.push(PathBuf::from("/dev"));
        let policy = FsPolicy {
            read_exec: system_read_exec(),
            read_only,
            read_write: vec![allowed.clone()],
        };
        let ruleset = Arc::new(build(&policy).unwrap());
        let run = |script: &str| {
            let rs = ruleset.clone();
            let mut cmd = std::process::Command::new("/bin/sh");
            cmd.arg("-c").arg(script);
            // SAFETY: prctl and one Landlock syscall, no allocation.
            unsafe {
                cmd.pre_exec(move || {
                    if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
                        return Err(io::Error::last_os_error());
                    }
                    rs.restrict_self()
                });
            }
            cmd.output().unwrap()
        };
        let ok = run(&format!(
            "cat {0}/a.txt && echo more > {0}/b.txt && mkdir {0}/sub && mv {0}/b.txt {0}/sub/",
            allowed.display()
        ));
        assert!(ok.status.success(), "{ok:?}");
        assert_eq!(String::from_utf8_lossy(&ok.stdout), "data");
        assert!(allowed.join("sub/b.txt").exists());
        let denied = run(&format!("cat {}/wg0.conf", secret.display()));
        assert!(!denied.status.success(), "{denied:?}");
        let denied = run(&format!("echo x > {}/new", secret.display()));
        assert!(!denied.status.success(), "{denied:?}");
        assert!(!secret.join("new").exists());
        let _ = std::fs::remove_dir_all(base);
    }

    #[test]
    fn missing_paths_are_skipped() {
        if abi().is_err() {
            return;
        }
        let policy = FsPolicy {
            read_exec: vec![PathBuf::from("/definitely/missing")],
            ..FsPolicy::default()
        };
        assert!(build(&policy).is_ok());
    }
}
