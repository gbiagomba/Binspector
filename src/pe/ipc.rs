//! Named-pipe IPC surface: whether an image serves a pipe, and whether it imports anything
//! capable of authenticating the caller.
//!
//! An adversarial review of this tool's output asked the question the scan could not answer:
//! for a given finding, is the code reachable from an unauthenticated surface? Full
//! reachability needs a disassembler and is out of scope. But the review's own strongest
//! example was built from imports alone: a bridge DLL that imports `CreateNamedPipeW`,
//! `ConnectNamedPipe` and `WaitNamedPipeW`, builds its own security descriptor with
//! `ConvertStringSecurityDescriptorToSecurityDescriptorW`, `SetSecurityDescriptorDacl` and
//! `SetEntriesInAclW`, and imports none of `ImpersonateNamedPipeClient`,
//! `GetNamedPipeClientProcessId`, `OpenThreadToken`, `GetTokenInformation`,
//! `CheckTokenMembership` or `AccessCheck`.
//!
//! `ImpersonateNamedPipeClient` is the canonical authorization primitive for a Windows
//! named-pipe server. Its absence is independent corroboration of "zero caller
//! authentication", derived from that one binary and checkable by anyone holding it.
//!
//! **This is narrowing, not reachability.** It says where a reviewer should look first, and
//! nothing more. It does not establish that the pipe is reachable, that the code behind it is
//! exploitable, or that no check happens: a server can authorize through a path no import
//! table records, such as a token handle obtained by other means, a check inside a statically
//! linked helper, or a primitive resolved through `GetProcAddress`. Like
//! `collect_safe_variants`, this module changes no severity and files no finding. It exists so
//! a reviewer does not misread one.
//!
//! Reference:
//! <https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-security-and-access-rights>

use serde::{Deserialize, Serialize};

use super::ImportRef;

/// Most names any one category will report. A crafted import table can carry hundreds of
/// synthesised names, and the point of the list is to give a reviewer somewhere to start, not
/// to be an inventory that fills a report.
const CAP: usize = 32;

/// Server-side pipe API family. Lowercased prefixes, so `A`/`W` and `Ex` variants all match,
/// the way `loader.rs` matches `LoadLibrary`.
const PIPE_SERVER: &[&str] = &["createnamedpipe", "connectnamedpipe", "disconnectnamedpipe"];

/// Client-side and either-end pipe use.
///
/// `WaitNamedPipe*` is a **client** API: a client waits for a free instance and then opens it
/// with `CreateFile`. `SetNamedPipeHandleState` and `PeekNamedPipe` are called from either end.
/// None of them can establish that an image serves a pipe, so they live here rather than in
/// `pipe_server`, which is what keeps that field's name true. Counting them as server evidence
/// would have reported an ordinary pipe client as `ServerUnauthorized`, this module's strongest
/// claim, on a binary that serves nothing.
const PIPE_CLIENT: &[&str] = &[
    "callnamedpipe",
    "transactnamedpipe",
    "waitnamedpipe",
    "setnamedpipehandlestate",
    "peeknamedpipe",
];

/// Security descriptor and ACL construction. Context, never a verdict on its own: an image
/// that builds its own DACL has made a decision about who may connect, which is worth seeing
/// next to the authorization column.
const DESCRIPTOR_BUILDERS: &[&str] = &[
    "convertstringsecuritydescriptortosecuritydescriptor",
    "setsecuritydescriptordacl",
    "setentriesinacl",
    "initializesecuritydescriptor",
    "addaccessallowedace",
];

/// Authorization primitives whose absence on a server is the signal. `accesscheck` covers
/// `AccessCheckByType` and its result-list variants; `checktokenmembership` covers `...Ex`.
const AUTHORIZATION: &[&str] = &[
    "impersonatenamedpipeclient",
    "getnamedpipeclientprocessid",
    "getnamedpipeclientsessionid",
    "openthreadtoken",
    "gettokeninformation",
    "checktokenmembership",
    "accesscheck",
];

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct IpcSurface {
    /// Named-pipe server primitives: CreateNamedPipe*, ConnectNamedPipe, WaitNamedPipe*,
    /// DisconnectNamedPipe, SetNamedPipeHandleState. Only CreateNamedPipe*, ConnectNamedPipe
    /// Server-only primitives: CreateNamedPipe*, ConnectNamedPipe, DisconnectNamedPipe. Only
    /// these can establish that an image serves a pipe.
    pub pipe_server: Vec<String>,
    /// Client-side and either-end pipe use. `CreateFile` on a pipe path cannot be told from any
    /// other file open, so it is absent.
    pub pipe_client: Vec<String>,
    /// Security descriptor and ACL construction:
    /// ConvertStringSecurityDescriptorToSecurityDescriptor*, SetSecurityDescriptorDacl,
    /// SetEntriesInAcl*, InitializeSecurityDescriptor, AddAccessAllowedAce.
    pub descriptor_builders: Vec<String>,
    /// Authorization primitives whose ABSENCE on a server is the signal:
    /// ImpersonateNamedPipeClient, GetNamedPipeClientProcessId, OpenThreadToken,
    /// GetTokenInformation, CheckTokenMembership, AccessCheck, AccessCheckByType,
    /// GetNamedPipeClientSessionId.
    pub authorization: Vec<String>,
    pub verdict: IpcVerdict,
}

#[derive(Copy, Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum IpcVerdict {
    /// No pipe IPC imports at all.
    #[default]
    None,
    /// Uses pipes as a client only.
    Client,
    /// A pipe server that imports at least one authorization primitive.
    Server,
    /// A pipe server importing none. Where to look first.
    ServerUnauthorized,
    /// A pipe server whose import table could not be read, so absence proves nothing.
    ServerUnknown,
}

impl IpcVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            IpcVerdict::None => "none",
            IpcVerdict::Client => "client",
            IpcVerdict::Server => "server",
            IpcVerdict::ServerUnauthorized => "server-unauthorized",
            IpcVerdict::ServerUnknown => "server-unknown",
        }
    }

    /// Whether this is worth a reviewer's attention first, for a `--missing`-style filter.
    ///
    /// `ServerUnauthorized` only. `ServerUnknown` is deliberately excluded: its entire point
    /// is that the absence could not be established, so letting it through a filter named for
    /// the weak case would smuggle the unprovable claim back in by the side door.
    pub fn is_weak(self) -> bool {
        matches!(self, IpcVerdict::ServerUnauthorized)
    }
}

impl IpcSurface {
    /// Classify the pipe-related imports of one image.
    ///
    /// `imports_known` must be false when no usable import table was read, which is the case
    /// for a packed image, a resource-only DLL, a managed assembly, and any format whose
    /// symbols this tool cannot attribute. That flag gates the absence argument and nothing
    /// else: see `decide`.
    pub fn from_imports(imports: &[ImportRef], imports_known: bool) -> Self {
        let mut s = Self::default();
        for i in imports {
            let lower = i.name.to_ascii_lowercase();
            // The four prefix sets do not overlap, so this order is not load-bearing today.
            // Authorization is tested first anyway, so that adding a `GetNamedPipeClient*`
            // name to the server family later cannot silently reclassify the one category
            // whose contents carry the weight.
            if starts_with_any(&lower, AUTHORIZATION) {
                s.authorization.push(i.name.clone());
            } else if starts_with_any(&lower, PIPE_SERVER) {
                s.pipe_server.push(i.name.clone());
            } else if starts_with_any(&lower, PIPE_CLIENT) {
                s.pipe_client.push(i.name.clone());
            } else if starts_with_any(&lower, DESCRIPTOR_BUILDERS) {
                s.descriptor_builders.push(i.name.clone());
            }
        }
        for v in [
            &mut s.pipe_server,
            &mut s.pipe_client,
            &mut s.descriptor_builders,
            &mut s.authorization,
        ] {
            tidy(v);
        }
        // Decided after the vectors are capped, so every claim is backed by a name the report
        // actually prints and a reviewer can check against the image.
        s.verdict = s.decide(imports_known);
        s
    }

    /// Whether the verdict says this image serves a pipe, which gates the report section.
    pub fn is_server(&self) -> bool {
        matches!(
            self.verdict,
            IpcVerdict::Server | IpcVerdict::ServerUnauthorized | IpcVerdict::ServerUnknown
        )
    }

    /// True when a server-only primitive is present. `pipe_server` being non-empty is not
    /// enough, because that family also contains calls a client makes.
    fn serves_a_pipe(&self) -> bool {
        self.pipe_server
            .iter()
            .any(|n| starts_with_any(&n.to_ascii_lowercase(), PIPE_SERVER))
    }

    fn decide(&self, imports_known: bool) -> IpcVerdict {
        if self.serves_a_pipe() {
            // Presence stands on its own: an incomplete table can hide a name, never invent
            // one, so an authorization import found in a partial table is still a real import.
            if !self.authorization.is_empty() {
                return IpcVerdict::Server;
            }
            // Absence is the opposite case, and this is the gate that matters most here. A
            // packed or resource-only PE has no import directory at all, so there is no table
            // for a name to be missing from, and concluding "imports no authorization
            // primitive" from an unreadable one would manufacture this tool's strongest claim
            // out of a parse failure. `scan::evidence` makes the same argument for
            // `imports_known`, and `pe::posture` makes it for `Unknown` mitigation states.
            if !imports_known {
                return IpcVerdict::ServerUnknown;
            }
            return IpcVerdict::ServerUnauthorized;
        }
        // Any pipe name that is not server-only is client-side or used by either end, so it
        // lands on the weaker verdict rather than on a server claim it cannot support.
        if !self.pipe_client.is_empty() || !self.pipe_server.is_empty() {
            return IpcVerdict::Client;
        }
        // Authorization or descriptor imports with no pipe at all are not an IPC surface. A
        // service that calls `AccessCheck` on its own objects is ordinary code.
        IpcVerdict::None
    }
}

fn starts_with_any(lower_name: &str, prefixes: &[&str]) -> bool {
    prefixes.iter().any(|p| lower_name.starts_with(p))
}

/// Sort, dedup and cap one category so the output is stable across runs and bounded.
///
/// Case-insensitive, because an image that carries both `CreateNamedPipeW` and
/// `createnamedpipew` names one primitive, not two. `CreateNamedPipeA` and `CreateNamedPipeW`
/// are different names and both survive: which one the image imports is checkable detail.
fn tidy(v: &mut Vec<String>) {
    v.sort_by_key(|n| n.to_ascii_lowercase());
    v.dedup_by(|a, b| a.eq_ignore_ascii_case(b));
    v.truncate(CAP);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn imports(names: &[&str]) -> Vec<ImportRef> {
        names
            .iter()
            .map(|n| ImportRef {
                library: "KERNEL32.dll".to_string(),
                name: n.to_string(),
            })
            .collect()
    }

    /// The exact case from the review, which is what this module was built for.
    #[test]
    fn a_pipe_server_with_no_authorization_import_is_where_to_look_first() {
        let s = IpcSurface::from_imports(
            &imports(&[
                "CreateNamedPipeW",
                "ConnectNamedPipe",
                "WaitNamedPipeW",
                "ConvertStringSecurityDescriptorToSecurityDescriptorW",
                "SetSecurityDescriptorDacl",
                "SetEntriesInAclW",
            ]),
            true,
        );
        assert_eq!(s.verdict, IpcVerdict::ServerUnauthorized);
        assert!(s.verdict.is_weak());
        assert!(s.is_server());
        // Only the server-only primitives land in `pipe_server`: WaitNamedPipeW is a client API
        // (a client waits for a free instance, then opens it with CreateFile), so counting it as
        // server evidence would report an ordinary client as ServerUnauthorized.
        assert_eq!(
            s.pipe_server.len(),
            2,
            "CreateNamedPipeW and ConnectNamedPipe"
        );
        assert!(
            s.pipe_client.iter().any(|n| n == "WaitNamedPipeW"),
            "the client-side wait belongs to the client column: {:?}",
            s.pipe_client
        );
        assert_eq!(s.descriptor_builders.len(), 3);
        assert!(s.authorization.is_empty());
        assert_eq!(s.verdict.as_str(), "server-unauthorized");
    }

    #[test]
    fn one_authorization_import_settles_it() {
        let s = IpcSurface::from_imports(
            &imports(&[
                "CreateNamedPipeW",
                "ConnectNamedPipe",
                "WaitNamedPipeW",
                "ConvertStringSecurityDescriptorToSecurityDescriptorW",
                "SetSecurityDescriptorDacl",
                "SetEntriesInAclW",
                "ImpersonateNamedPipeClient",
            ]),
            true,
        );
        assert_eq!(s.verdict, IpcVerdict::Server);
        assert!(!s.verdict.is_weak());
        assert!(s.is_server());
        assert_eq!(s.authorization, vec!["ImpersonateNamedPipeClient"]);
    }

    /// The one test that must not be wrong. Without a readable import table there is nothing
    /// for a name to be absent from, so the absence claim is unavailable at any strength.
    #[test]
    fn a_client_that_only_waits_on_a_pipe_is_not_reported_as_a_server() {
        // The false positive the server-only gate exists to prevent: a client importing the wait
        // API and nothing server-side must never carry this module's strongest claim.
        let s = IpcSurface::from_imports(
            &imports(&["WaitNamedPipeW", "SetNamedPipeHandleState", "PeekNamedPipe"]),
            true,
        );
        assert_eq!(s.verdict, IpcVerdict::Client);
        assert!(!s.verdict.is_weak());
        assert!(!s.is_server());
        assert!(s.pipe_server.is_empty());
    }

    #[test]
    fn an_unreadable_import_table_can_never_produce_the_unauthorized_verdict() {
        let s =
            IpcSurface::from_imports(&imports(&["CreateNamedPipeW", "ConnectNamedPipe"]), false);
        assert_eq!(s.verdict, IpcVerdict::ServerUnknown);
        assert_ne!(s.verdict, IpcVerdict::ServerUnauthorized);
        assert!(!s.verdict.is_weak(), "an unprovable claim is not a lead");
        assert!(s.is_server(), "it still serves a pipe");

        // Presence is unaffected by an incomplete table: it can hide a name, never invent one.
        let found = IpcSurface::from_imports(
            &imports(&["CreateNamedPipeW", "ImpersonateNamedPipeClient"]),
            false,
        );
        assert_eq!(found.verdict, IpcVerdict::Server);
    }

    #[test]
    fn client_only_imports_are_a_client() {
        let s = IpcSurface::from_imports(&imports(&["CallNamedPipeW", "TransactNamedPipe"]), true);
        assert_eq!(s.verdict, IpcVerdict::Client);
        assert!(!s.is_server());
        assert!(!s.verdict.is_weak());
        assert_eq!(s.pipe_client.len(), 2);
        assert!(s.pipe_server.is_empty());
    }

    /// `WaitNamedPipe*` is how a client finds a free instance before `CreateFile`, and
    /// `SetNamedPipeHandleState` is called on either end. Neither can carry a server verdict,
    /// or every pipe client in the bundle would be reported as an unauthenticated server.
    #[test]
    fn the_client_reachable_half_of_the_server_family_is_not_a_server() {
        let s = IpcSurface::from_imports(
            &imports(&["WaitNamedPipeW", "SetNamedPipeHandleState", "CreateFileW"]),
            true,
        );
        assert_eq!(s.verdict, IpcVerdict::Client);
        assert!(!s.is_server());
    }

    #[test]
    fn no_pipe_imports_means_no_surface() {
        let s = IpcSurface::from_imports(&imports(&["GetLastError", "Sleep", "CreateFileW"]), true);
        assert_eq!(s.verdict, IpcVerdict::None);
        assert_eq!(s.verdict.as_str(), "none");
        assert!(!s.is_server());
        assert!(!s.verdict.is_weak());
        assert!(s.pipe_server.is_empty());
        assert!(s.pipe_client.is_empty());
        assert!(s.descriptor_builders.is_empty());
        assert!(s.authorization.is_empty());
    }

    /// Authorization imports without a pipe are ordinary code. A service calling `AccessCheck`
    /// on its own objects has no IPC surface here, and calling it one would invert the signal.
    #[test]
    fn authorization_imports_alone_are_not_an_ipc_surface() {
        let s = IpcSurface::from_imports(
            &imports(&[
                "AccessCheck",
                "GetTokenInformation",
                "CheckTokenMembership",
                "SetSecurityDescriptorDacl",
            ]),
            true,
        );
        assert_eq!(s.verdict, IpcVerdict::None);
        assert!(!s.is_server());
        assert_eq!(s.authorization.len(), 3);
        assert_eq!(s.descriptor_builders.len(), 1);
    }

    #[test]
    fn case_and_ansi_wide_variants_both_match() {
        let s = IpcSurface::from_imports(
            &imports(&[
                "CREATENAMEDPIPEA",
                "createnamedpipew",
                "connectnamedpipe",
                "setentriesinacla",
                "SetEntriesInAclW",
                "accesscheckbytype",
                "GetNamedPipeClientSessionId",
            ]),
            true,
        );
        assert_eq!(s.pipe_server.len(), 3, "both A and W, plus Connect");
        assert_eq!(s.descriptor_builders.len(), 2, "SetEntriesInAcl A and W");
        assert_eq!(
            s.authorization,
            vec!["accesscheckbytype", "GetNamedPipeClientSessionId"],
            "AccessCheckByType is reached by the AccessCheck prefix"
        );
        assert_eq!(s.verdict, IpcVerdict::Server);
    }

    #[test]
    fn each_category_is_sorted_deduplicated_and_capped() {
        let mut names = vec![
            "WaitNamedPipeW".to_string(),
            "ConnectNamedPipe".to_string(),
            "CreateNamedPipeW".to_string(),
            // Same primitive spelled differently, which is one name, not two.
            "createnamedpipew".to_string(),
        ];
        // A crafted table cannot fill a report.
        names.extend((0..40).map(|i| format!("CreateNamedPipeW{i:02}")));
        let s = IpcSurface::from_imports(
            &imports(&names.iter().map(|n| n.as_str()).collect::<Vec<_>>()),
            true,
        );
        assert_eq!(s.pipe_server.len(), CAP);
        let first: Vec<&str> = s.pipe_server.iter().take(3).map(|n| n.as_str()).collect();
        assert_eq!(
            first,
            vec!["ConnectNamedPipe", "CreateNamedPipeW", "CreateNamedPipeW00"],
            "sorted case-insensitively, and the duplicate spelling is gone"
        );
        let mut sorted = s.pipe_server.clone();
        sorted.sort_by_key(|n| n.to_ascii_lowercase());
        assert_eq!(sorted, s.pipe_server);
        // Truncation must not change what the image is: the server names sort first anyway.
        assert_eq!(s.verdict, IpcVerdict::ServerUnauthorized);
    }
}
