//! Whether a permission grant's scope covers a delivered grant key.
//!
//! Two features need this one question answered the same way. The encryption
//! control plane asks it of a delivery record: may a reader holding *this*
//! grant reach key material delivered for *that* role? Grant-key records ask
//! it of a key they are about to hand out: is this grant the reason that key
//! may exist? It is the most security-sensitive rule in the encryption work,
//! and answering it in two places would be two chances to get it wrong
//! differently — so it is answered once, here.
//!
//! So it sits beside the rest of the encryption primitives rather than inside
//! either feature that asks it, and it is a pure function of a grant scope, a
//! delivered scope, and optionally a protocol definition. Nothing here reads a
//! store.
//!
//! # What is here and what is not
//!
//! The **Read** direction is complete: eligibility, and whether a Read grant
//! covers a delivered path. The **Write** direction, enumerating the scopes a
//! grant delivers, and the protocol-scoped delivered direction belong to
//! grant-key records themselves and are not answered here. The eligibility
//! helpers already admit Write scopes, so that side needs nothing reshaped.

use crate::interfaces::messages::protocols::{Action, Can, Definition, RuleSet};
use crate::permissions::{PermissionScope, RecordsMethod, RecordsSelector};
use crate::protocols::parse_cross_protocol_ref;

use std::collections::BTreeSet;

/// A grant scope that could deliver a grant key.
///
/// Eligibility is deliberately narrow. The scope must name the Records
/// interface and a Read or Write method, must carry a protocol as an exact
/// string, and must not be scoped to a context: a delivered key is addressed by
/// protocol path, so a context scope would be matching on a dimension the
/// target does not have, and treating it as unscoped would silently widen it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EligibleGrantScope<'a> {
    pub protocol: &'a str,
    /// Absent means the whole protocol.
    pub protocol_path: Option<&'a str>,
    pub method: RecordsMethod,
}

/// The scope a delivered grant key names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeliveredScope<'a> {
    pub protocol: &'a str,
    /// Absent means the key is protocol-scoped rather than path-scoped.
    pub protocol_path: Option<&'a str>,
}

/// Reads a grant scope as an eligible one, or rejects it.
pub fn eligible_grant_scope(scope: &PermissionScope) -> Option<EligibleGrantScope<'_>> {
    let PermissionScope::Records(records) = scope else {
        return None;
    };
    if !matches!(records.method, RecordsMethod::Read | RecordsMethod::Write) {
        return None;
    }
    let protocol_path = match &records.selector {
        Some(RecordsSelector::ProtocolPath(path)) => Some(path.0.as_str()),
        // A context-scoped grant delivers no key.
        Some(RecordsSelector::ContextId(_)) => return None,
        None => None,
    };
    Some(EligibleGrantScope {
        protocol: records.protocol.as_str(),
        protocol_path,
        method: records.method.clone(),
    })
}

/// Whether a **Read** grant covers a delivered key's scope.
///
/// Three ways it can, in order of how much they need to know:
///
/// 1. The grant names no path, so it covers the whole protocol — including a
///    protocol-scoped delivered key, and any path within it.
/// 2. The grant names path `P`, and the delivered path is `P` or beneath it.
///    Boundary-aware, so `thread` does not cover `threading`.
/// 3. The grant names path `P`, and the delivered path is a keyed role that
///    some `read` action within `P`'s subtree references. A reader given a
///    subtree implicitly reaches the roles that subtree reads *through*,
///    wherever in the protocol those roles are declared — the delivered key is
///    what makes the subtree usable at all.
///
/// Only the third needs the definition. Passing `None` answers the first two
/// and returns `false` for the third rather than guessing, which is what lets a
/// caller decide the cheap cases before paying for a definition lookup.
///
/// A path-scoped grant never covers a protocol-scoped delivered key: the
/// protocol key opens every path, and a grant over one subtree is not authority
/// over all of them.
pub fn read_grant_covers_delivered_scope(
    grant: &EligibleGrantScope<'_>,
    delivered: &DeliveredScope<'_>,
    definition: Option<&Definition>,
) -> bool {
    if grant.method != RecordsMethod::Read || grant.protocol != delivered.protocol {
        return false;
    }
    let Some(grant_path) = grant.protocol_path else {
        return true;
    };
    let Some(delivered_path) = delivered.protocol_path else {
        return false;
    };
    if matches_subtree(grant_path, delivered_path) {
        return true;
    }
    definition.is_some_and(|definition| {
        is_keyed_role(definition, delivered_path)
            && read_roles_under(definition, grant_path).contains(delivered_path)
    })
}

/// Local role paths that the rule set at `scope_path`, or anything beneath it,
/// grants read through.
///
/// Cross-protocol role references are excluded: they name membership this
/// protocol does not define. The role must still be keyed, because a
/// configuration that keeps a role but drops its `$keyAgreement` stops it
/// conveying key material, and a subtree delegate must lose that reach with
/// it. Referencing role `R` reaches `R` alone and not its descendants — the
/// reference names a role, not a subtree.
pub fn read_roles_under(definition: &Definition, scope_path: &str) -> BTreeSet<String> {
    fn collect(definition: &Definition, rule_set: &RuleSet, found: &mut BTreeSet<String>) {
        for action in &rule_set.actions {
            if let Action::Role(role_action) = action {
                if role_action.can.contains(&Can::Read)
                    && parse_cross_protocol_ref(&role_action.role).is_none()
                    && is_keyed_role(definition, &role_action.role)
                {
                    found.insert(role_action.role.clone());
                }
            }
        }
        for child in rule_set.rules.values() {
            collect(definition, child, found);
        }
    }

    let mut found = BTreeSet::new();
    if let Some(rule_set) = definition.rule_at(scope_path) {
        collect(definition, rule_set, &mut found);
    }
    found
}

/// Whether `protocol_path` is a role this protocol declares *and* keys.
pub fn is_keyed_role(definition: &Definition, protocol_path: &str) -> bool {
    definition
        .rule_at(protocol_path)
        .is_some_and(|rule_set| rule_set.role == Some(true) && rule_set.key_agreement.is_some())
}

/// Whether `path` is `scope` or lies beneath it, respecting path boundaries.
fn matches_subtree(scope: &str, path: &str) -> bool {
    path == scope || (path.starts_with(scope) && path.as_bytes().get(scope.len()) == Some(&b'/'))
}

#[cfg(test)]
mod tests {
    use super::*;

    use serde_json::json;

    use crate::permissions::{ProtocolPath, RecordsScope};

    /// `thread` reads through `member`; `thread/notes` reads through
    /// `archivist`, which is declared at the root; `plain` reads through
    /// nothing; `unkeyed` is a role the configuration does not key; `foreign`
    /// is read through a cross-protocol reference.
    fn definition() -> Definition {
        serde_json::from_value(json!({
            "protocol": "http://example.com/threads",
            "published": true,
            "types": {
                "member": {}, "archivist": {}, "unkeyed": {},
                "thread": {}, "notes": {}, "plain": {}, "leaf": {}
            },
            "structure": {
                "member": { "$role": true, "$keyAgreement": { "publicKeyJwk": {
                    "kty": "OKP", "crv": "X25519",
                    "x": "Xf7dO2vUf2-ijuFdlp1bsOpTd01Ii9r53xxuASSz7yI"
                } } },
                "archivist": { "$role": true, "$keyAgreement": { "publicKeyJwk": {
                    "kty": "OKP", "crv": "X25519",
                    "x": "Xf7dO2vUf2-ijuFdlp1bsOpTd01Ii9r53xxuASSz7yI"
                } } },
                "unkeyed": { "$role": true },
                "plain": {},
                "thread": {
                    "$actions": [{ "role": "member", "can": ["read"] }],
                    "notes": {
                        "$actions": [
                            { "role": "archivist", "can": ["read"] },
                            { "role": "unkeyed", "can": ["read"] },
                            { "role": "other:reader", "can": ["read"] }
                        ],
                        "leaf": {}
                    }
                }
            }
        }))
        .expect("definition fixture must deserialize")
    }

    fn scope(method: RecordsMethod, protocol_path: Option<&str>) -> PermissionScope {
        PermissionScope::Records(RecordsScope {
            protocol: "http://example.com/threads".to_string(),
            method,
            selector: protocol_path
                .map(|path| RecordsSelector::ProtocolPath(ProtocolPath(path.to_string()))),
        })
    }

    fn covers(
        method: RecordsMethod,
        grant_path: Option<&str>,
        delivered_path: Option<&str>,
        with_definition: bool,
    ) -> bool {
        let scope = scope(method, grant_path);
        let eligible = eligible_grant_scope(&scope).expect("the fixture scope is eligible");
        let definition = with_definition.then(definition);
        read_grant_covers_delivered_scope(
            &eligible,
            &DeliveredScope {
                protocol: "http://example.com/threads",
                protocol_path: delivered_path,
            },
            definition.as_ref(),
        )
    }

    // Covers: ENBOX-ENC-003
    // The whole Read coverage rule as a table, exercised directly rather than
    // through one of its callers. It has two, and a rule this
    // security-sensitive should not be testable only through delivery
    // visibility.
    #[test]
    fn read_coverage_table() {
        use RecordsMethod::{Read, Write};

        for (grant_path, delivered_path, with_definition, expected, why) in [
            // A grant over the whole protocol covers everything in it,
            // including a protocol-scoped key, and needs no definition.
            (
                None,
                None,
                false,
                true,
                "protocol grant covers the protocol key",
            ),
            (
                None,
                Some("member"),
                false,
                true,
                "protocol grant covers any path",
            ),
            (
                None,
                Some("thread/notes"),
                false,
                true,
                "protocol grant covers nested paths",
            ),
            // A path-scoped grant covers its own path and its descendants.
            (
                Some("thread"),
                Some("thread"),
                false,
                true,
                "a path covers itself",
            ),
            (
                Some("thread"),
                Some("thread/notes"),
                false,
                true,
                "and its descendants",
            ),
            (
                Some("thread"),
                Some("thread/notes/leaf"),
                false,
                true,
                "however deep",
            ),
            // But never a protocol-scoped key: that key opens every path, and
            // authority over one subtree is not authority over all of them.
            (
                Some("thread"),
                None,
                false,
                false,
                "a path grant is not the protocol key",
            ),
            (
                Some("thread"),
                None,
                true,
                false,
                "not even with a definition",
            ),
            // Path boundaries are respected, so no prefix collisions.
            (
                Some("thread"),
                Some("threading"),
                true,
                false,
                "'threading' is not under 'thread'",
            ),
            // The keyed-role exception: `thread` reads through `member`.
            (
                Some("thread"),
                Some("member"),
                true,
                true,
                "a subtree reaches the role it reads through",
            ),
            (
                Some("thread"),
                Some("member"),
                false,
                false,
                "undecidable without a definition, so not reachable",
            ),
            // Reached from anywhere inside the granted subtree, wherever the
            // role itself is declared.
            (
                Some("thread"),
                Some("archivist"),
                true,
                true,
                "including from deeper in the subtree",
            ),
            // A subtree that reads through nothing reaches nothing.
            (
                Some("plain"),
                Some("member"),
                true,
                false,
                "'plain' reads through no role",
            ),
            // A role the configuration no longer keys conveys no key material.
            (
                Some("thread"),
                Some("unkeyed"),
                true,
                false,
                "an unkeyed role is not reachable",
            ),
            // Cross-protocol references name membership this protocol does not
            // define.
            (
                Some("thread"),
                Some("other:reader"),
                true,
                false,
                "cross-protocol refs are excluded",
            ),
            // Referencing a role reaches the role, not its subtree.
            (
                Some("thread"),
                Some("member/child"),
                true,
                false,
                "a referenced role is not a subtree",
            ),
        ] {
            assert_eq!(
                covers(Read, grant_path, delivered_path, with_definition),
                expected,
                "read grant {grant_path:?} over delivered {delivered_path:?} \
                 (definition: {with_definition}): {why}"
            );
        }

        // The Write direction is not answered here: a Write grant covers
        // nothing through this predicate, however it is scoped.
        for grant_path in [None, Some("thread")] {
            for delivered_path in [None, Some("thread"), Some("member")] {
                assert!(
                    !covers(Write, grant_path, delivered_path, true),
                    "the Read predicate must not answer for a Write grant"
                );
            }
        }
    }

    // Covers: ENBOX-ENC-003
    // Eligibility is what keeps a scope that means something else from being
    // read as an unscoped one.
    #[test]
    fn only_eligible_scopes_deliver_keys() {
        assert!(
            eligible_grant_scope(&scope(RecordsMethod::Read, None)).is_some(),
            "a protocol-scoped Records Read grant is eligible"
        );
        assert!(
            eligible_grant_scope(&scope(RecordsMethod::Write, Some("thread"))).is_some(),
            "so is a Write grant — the Write half slots in later"
        );
        assert_eq!(
            eligible_grant_scope(&PermissionScope::Records(RecordsScope {
                protocol: "http://example.com/threads".to_string(),
                method: RecordsMethod::Read,
                selector: Some(RecordsSelector::ContextId(crate::permissions::ContextId(
                    "thread-1".to_string()
                ))),
            })),
            None,
            "a context-scoped grant delivers no key: treating it as unscoped \
             would silently widen it to the whole protocol"
        );
        assert_eq!(
            eligible_grant_scope(&scope(RecordsMethod::Delete, None)),
            None,
            "a method that cannot read or write key material is not eligible"
        );
    }
}
