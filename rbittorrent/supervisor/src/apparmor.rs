//! AppArmor confinement, the filesystem sandbox on Home Assistant OS.
//!
//! HAOS kernels enable AppArmor only (`CONFIG_LSM="apparmor"`, no Landlock),
//! and the Supervisor loads the app's `apparmor.txt` under the app's slug.
//! rtbit and the Ingress proxy run in its child profiles `<slug>//rtbit` and
//! `<slug>//ingress`: the forked child changes to its profile
//! ([`ProfileSwitch`]) before it sets `no_new_privs`, which would make
//! AppArmor refuse the change, and then runs its binary in that profile.
//! This module also reads the labels from `/proc` so the supervisor can tell
//! whether its own profile is the app's, and prove that a child really runs
//! in its child profile before trusting it.

use std::ffi::CStr;
use std::io;
use std::path::Path;

/// The app's slug ends in this; the Supervisor prefixes a repository id
/// (`local_rbittorrent`, `1a2b3c4d_rbittorrent`).
pub const PROFILE_SUFFIX: &str = "rbittorrent";
/// rtbit's child profile.
pub const RTBIT_CHILD: &str = "rtbit";
/// The Ingress proxy's child profile.
pub const INGRESS_CHILD: &str = "ingress";

/// A task's AppArmor label: `name (mode)`, or `unconfined`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Label {
    pub name: String,
    /// `enforce`, `complain`, `kill`, ...; empty for `unconfined`.
    pub mode: String,
}

impl Label {
    pub fn parse(raw: &str) -> Option<Self> {
        let raw = raw.trim_matches(|c: char| c.is_whitespace() || c == '\0');
        if raw.is_empty() {
            return None;
        }
        Some(match raw.rsplit_once(" (") {
            Some((name, mode)) => Self {
                name: name.to_owned(),
                mode: mode.trim_end_matches(')').to_owned(),
            },
            None => Self {
                name: raw.to_owned(),
                mode: String::new(),
            },
        })
    }

    pub fn enforced(&self) -> bool {
        self.mode == "enforce"
    }
}

impl std::fmt::Display for Label {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.mode.is_empty() {
            f.write_str(&self.name)
        } else {
            write!(f, "{} ({})", self.name, self.mode)
        }
    }
}

/// The AppArmor label of `/proc/<pid>` (`self` for this process). With LSM
/// stacking the label is in `attr/apparmor/`; older kernels only have the
/// shared `attr/current`.
/// Another LSM's label in `attr/current` (SELinux) is never accepted by
/// [`app_profile`] or [`is_child`].
pub fn label_of(proc_dir: &Path) -> Option<Label> {
    let read = |p: &str| std::fs::read_to_string(proc_dir.join(p)).ok();
    read("attr/apparmor/current")
        .or_else(|| read("attr/current"))
        .as_deref()
        .and_then(Label::parse)
}

/// The app's own profile (enforced) that this process runs in, or why not.
pub fn own_profile() -> Result<String, String> {
    match label_of(Path::new("/proc/self")) {
        None => Err("AppArmor is not active".to_owned()),
        Some(l) => app_profile(&l),
    }
}

/// `Ok(profile name)` when `label` is the app's profile, enforced.
pub fn app_profile(label: &Label) -> Result<String, String> {
    if label.name == "unconfined" {
        return Err("the app runs unconfined (AppArmor disabled for it)".to_owned());
    }
    if label.name.contains("//") || !label.name.ends_with(PROFILE_SUFFIX) {
        return Err(format!(
            "the app runs under the AppArmor profile `{label}`, not its own (apparmor.txt)"
        ));
    }
    if !label.enforced() {
        return Err(format!(
            "the app's AppArmor profile is not enforced (`{label}`)"
        ));
    }
    Ok(label.name.clone())
}

/// Whether `label` confines a task to `<profile>//<child>`, enforced: the
/// child profile alone, or stacked on the app's profile
/// (`<profile>//&<profile>//<child>`, never narrower than the child).
pub fn is_child(label: &Label, profile: &str, child: &str) -> bool {
    let want = format!("{profile}//{child}");
    let parts: Vec<&str> = label.name.split("//&").collect();
    label.enforced()
        && parts.contains(&want.as_str())
        && parts.iter().all(|p| *p == want || *p == profile)
}

/// Where a task changes its own profile: the AppArmor-specific file with LSM
/// stacking, the shared one on older kernels.
const ATTR_CURRENT: [&CStr; 2] = [
    c"/proc/self/attr/apparmor/current",
    c"/proc/self/attr/current",
];

/// Moves the calling task to the profile `<profile>//<child>`
/// (`change_profile`, allowed by the app's profile). Built before `fork`, so
/// that the forked child only makes syscalls.
#[derive(Debug, Clone)]
pub struct ProfileSwitch {
    command: Vec<u8>,
}

impl ProfileSwitch {
    pub fn new(profile: &str, child: &str) -> Self {
        Self {
            command: format!("changeprofile {profile}//{child}").into_bytes(),
        }
    }

    /// Changes the profile now; it applies to this task and everything it
    /// runs. Must come before `no_new_privs`. Async-signal-safe: open,
    /// write, close, and errors built from an errno.
    pub fn apply(&self) -> io::Result<()> {
        for path in ATTR_CURRENT {
            // SAFETY: a NUL-terminated path; the fd is closed below.
            let fd = unsafe { libc::open(path.as_ptr(), libc::O_WRONLY | libc::O_CLOEXEC) };
            if fd < 0 {
                let err = io::Error::last_os_error();
                if err.raw_os_error() == Some(libc::ENOENT) {
                    continue;
                }
                return Err(err);
            }
            // SAFETY: writes `command`, which outlives the call.
            let n = unsafe { libc::write(fd, self.command.as_ptr().cast(), self.command.len()) };
            let err = io::Error::last_os_error();
            // SAFETY: the fd opened above.
            unsafe { libc::close(fd) };
            return match usize::try_from(n) {
                Ok(n) if n == self.command.len() => Ok(()),
                Ok(_) => Err(io::Error::from_raw_os_error(libc::EIO)),
                Err(_) => Err(err),
            };
        }
        Err(io::Error::from_raw_os_error(libc::ENOENT))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn a_failed_profile_switch_stops_the_child() {
        use std::os::unix::process::CommandExt as _;
        let marker = std::env::temp_dir().join(format!("rbt-switch-{}", std::process::id()));
        // No such profile: with AppArmor the change is refused, without it
        // the write fails. Either way the child must not run.
        let switch = ProfileSwitch::new("rbt-test-no-such-profile", RTBIT_CHILD);
        assert_eq!(
            switch.command,
            b"changeprofile rbt-test-no-such-profile//rtbit"
        );
        let mut cmd = std::process::Command::new("/bin/sh");
        cmd.arg("-c").arg(format!("touch {}", marker.display()));
        // SAFETY: `apply` only makes syscalls on pre-allocated data.
        unsafe {
            cmd.pre_exec(move || switch.apply());
        }
        assert!(cmd.status().is_err(), "the exec must fail");
        assert!(!marker.exists(), "the child ran");
    }

    #[test]
    fn labels_are_parsed() {
        let l = Label::parse("local_rbittorrent//rtbit (enforce)\n").unwrap();
        assert_eq!(l.name, "local_rbittorrent//rtbit");
        assert!(l.enforced());
        let u = Label::parse("unconfined\n").unwrap();
        assert_eq!(u.name, "unconfined");
        assert!(!u.enforced());
        assert!(Label::parse("\n").is_none());
        assert_eq!(l.to_string(), "local_rbittorrent//rtbit (enforce)");
    }

    #[test]
    fn only_the_apps_enforced_profile_counts() {
        let ok = |s: &str| app_profile(&Label::parse(s).unwrap());
        assert_eq!(
            ok("1a2b3c4d_rbittorrent (enforce)").unwrap(),
            "1a2b3c4d_rbittorrent"
        );
        assert_eq!(ok("rbittorrent (enforce)").unwrap(), "rbittorrent");
        assert!(ok("docker-default (enforce)").is_err());
        assert!(ok("unconfined").is_err());
        assert!(ok("local_rbittorrent (complain)").is_err());
        assert!(ok("local_rbittorrent//rtbit (enforce)").is_err());
    }

    #[test]
    fn a_child_must_be_in_its_own_enforced_profile() {
        let l = |s: &str| Label::parse(s).unwrap();
        let p = "local_rbittorrent";
        assert!(is_child(
            &l("local_rbittorrent//rtbit (enforce)"),
            p,
            RTBIT_CHILD
        ));
        // Stacked on the app's profile, in either order.
        assert!(is_child(
            &l("local_rbittorrent//&local_rbittorrent//rtbit (enforce)\n"),
            p,
            RTBIT_CHILD
        ));
        assert!(is_child(
            &l("local_rbittorrent//rtbit//&local_rbittorrent (enforce)"),
            p,
            RTBIT_CHILD
        ));
        assert!(!is_child(
            &l("local_rbittorrent//&local_rbittorrent//rtbit (mixed)"),
            p,
            RTBIT_CHILD
        ));
        assert!(!is_child(
            &l("local_rbittorrent//&unconfined (enforce)"),
            p,
            RTBIT_CHILD
        ));
        assert!(!is_child(
            &l("local_rbittorrent//rtbit//&docker-default (enforce)"),
            p,
            RTBIT_CHILD
        ));
        assert!(!is_child(
            &l("local_rbittorrent//&local_rbittorrent//ingress (enforce)"),
            p,
            RTBIT_CHILD
        ));
        assert!(!is_child(
            &l("local_rbittorrent//rtbit (complain)"),
            p,
            RTBIT_CHILD
        ));
        assert!(!is_child(&l("local_rbittorrent (enforce)"), p, RTBIT_CHILD));
        assert!(!is_child(
            &l("local_rbittorrent//ingress (enforce)"),
            p,
            RTBIT_CHILD
        ));
        assert!(!is_child(&l("other//rtbit (enforce)"), p, RTBIT_CHILD));
        assert!(!is_child(&l("unconfined"), p, RTBIT_CHILD));
    }
}
