//! AppArmor confinement, the filesystem sandbox on Home Assistant OS.
//!
//! HAOS kernels enable AppArmor only (`CONFIG_LSM="apparmor"`, no Landlock),
//! and the Supervisor loads the app's `apparmor.txt` under the app's slug.
//! That profile switches rtbit and the Ingress proxy to the child profiles
//! `<slug>//rtbit` and `<slug>//ingress` when they are executed. This module
//! reads the labels from `/proc` so the supervisor can tell whether its own
//! profile is the app's, and prove that a child really runs in its child
//! profile before trusting it.

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

/// Whether `label` is `<profile>//<child>`, enforced.
pub fn is_child(label: &Label, profile: &str, child: &str) -> bool {
    label.enforced()
        && label
            .name
            .strip_prefix(profile)
            .and_then(|rest| rest.strip_prefix("//"))
            == Some(child)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

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
