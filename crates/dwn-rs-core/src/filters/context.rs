//! Boundary-aware protocol context helpers.
//!
//! Covers `DWN-PROTO-001`, `DWN-PROTO-002`.
//!
//! TypeScript parity source: `Records.convertFilter` maps `contextId` to
//! `{ subtree: contextId }` and `Records.validateNestedProtocolPathScope`
//! pins nested-path collection filters to a direct parent (`parentId`), the
//! target path, or an ancestor context. A raw lexical prefix is insufficient:
//! scope `a/b` must select `a/b` and `a/b/...` but never `a/bc`.

use crate::filters::message_filters::Records as RecordsFilter;

/// Returns `true` iff `candidate` is inside the `scope` subtree.
///
/// Exact equality wins; otherwise the candidate must start with
/// `"{scope}/"`. This is the single predicate behind `Filter::Subtree` for
/// `contextId` — use it instead of `str::starts_with` on the raw scope.
pub fn is_context_subtree_match(candidate: &str, scope: &str) -> bool {
    candidate == scope || candidate.starts_with(&format!("{scope}/"))
}

/// Validates the pinned Enbox nested-scope rule for collection filters.
///
/// Mirrors `Records.validateNestedProtocolPathScope` at the parity baseline
/// (`enboxorg/enbox@c63bf42`):
/// - flat `protocolPath` values (no `/`) need no scope;
/// - `parentId` without `contextId` selects direct parents — accepted;
/// - `allow_bounded_path_wide` covers the bounded Subscribe initial page,
///   which may omit scope because its snapshot is explicitly capped;
/// - otherwise `contextId` must address the target path or an ancestor:
///   at most as many non-empty segments as the protocol path has.
///
/// Deeper-than-path, empty-segment, and trailing-separator inputs are
/// rejected. The `$encryption/*` control-path carve-out lives with the
/// encryption-control projection owned elsewhere and is intentionally absent
/// here.
///
/// The returned error is the reason only, without a method-specific code:
/// each calling handler prefixes its own upstream code
/// (`RecordsQuery…`, `RecordsCount…`, `RecordsSubscribe…`), which TypeScript
/// asserts per method in `status.detail`.
pub fn validate_nested_protocol_path_scope(
    filter: &RecordsFilter,
    allow_bounded_path_wide: bool,
) -> Result<(), String> {
    let Some(protocol_path) = filter.protocol_path.as_deref() else {
        return Ok(());
    };
    if !protocol_path.contains('/') {
        return Ok(());
    }
    // Encryption-control paths only look nested. They are virtual, declared by
    // no protocol, and carry their context in tags rather than in a record
    // hierarchy, so demanding a parent or ancestor context of them would rule
    // out every well-formed control query.
    if crate::encryption::control::is_encryption_control_path(protocol_path) {
        return Ok(());
    }

    if filter.parent_id.is_some() && filter.context_id.is_none() {
        return Ok(());
    }

    if filter.context_id.is_none() && allow_bounded_path_wide {
        return Ok(());
    }

    let protocol_path_depth = protocol_path.split('/').count();
    if let Some(context_id) = filter.context_id.as_deref() {
        let segments: Vec<&str> = context_id.split('/').collect();
        if segments.len() <= protocol_path_depth && segments.iter().all(|s| !s.is_empty()) {
            return Ok(());
        }
    }

    Err(format!(
        "for nested protocol path '{protocol_path}' must include parentId or a contextId selecting that path or one of its ancestors"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn filter(
        protocol_path: Option<&str>,
        parent_id: Option<&str>,
        context_id: Option<&str>,
    ) -> RecordsFilter {
        RecordsFilter {
            protocol_path: protocol_path.map(str::to_string),
            parent_id: parent_id.map(str::to_string),
            context_id: context_id.map(str::to_string),
            ..Default::default()
        }
    }

    // Covers: DWN-PROTO-001, DWN-PROTO-002
    #[test]
    fn subtree_predicate_is_boundary_aware() {
        assert!(is_context_subtree_match("a/b", "a/b"));
        assert!(is_context_subtree_match("a/b/c", "a/b"));
        assert!(is_context_subtree_match("a/b/c/d", "a/b"));
        assert!(!is_context_subtree_match("a/bc", "a/b"));
        assert!(!is_context_subtree_match("a/b-sibling", "a/b"));
        assert!(!is_context_subtree_match("a/branches/child", "a/branch"));
        assert!(!is_context_subtree_match("a", "a/b"));
    }

    // Covers: DWN-PROTO-001, DWN-PROTO-002
    #[test]
    fn nested_scope_accepts_pinned_combinations() {
        // Flat path needs no scope.
        assert!(
            validate_nested_protocol_path_scope(&filter(Some("post"), None, None), false).is_ok()
        );
        // No protocol path needs no scope.
        assert!(validate_nested_protocol_path_scope(&filter(None, None, None), false).is_ok());
        // Direct-parent selection via parentId.
        assert!(validate_nested_protocol_path_scope(
            &filter(Some("thread/message"), Some("parent-1"), None),
            false
        )
        .is_ok());
        // Exact target context and ancestor context.
        assert!(validate_nested_protocol_path_scope(
            &filter(Some("thread/message"), None, Some("ctx-a/ctx-b")),
            false
        )
        .is_ok());
        assert!(validate_nested_protocol_path_scope(
            &filter(Some("thread/message"), None, Some("ctx-a")),
            false
        )
        .is_ok());
    }

    // Covers: DWN-PROTO-001, DWN-PROTO-002
    #[test]
    fn nested_scope_rejects_unscoped_and_malformed() {
        // Missing scope on nested path.
        assert!(validate_nested_protocol_path_scope(
            &filter(Some("thread/message"), None, None),
            false
        )
        .is_err());
        // Deeper-than-path context.
        assert!(validate_nested_protocol_path_scope(
            &filter(Some("thread/message"), None, Some("a/b/c")),
            false
        )
        .is_err());
        // Trailing separator and empty segments.
        for bad in ["a/b/", "a//b", "/a/b", ""] {
            assert!(
                validate_nested_protocol_path_scope(
                    &filter(Some("thread/message"), None, Some(bad)),
                    false
                )
                .is_err(),
                "context {bad:?} should be rejected"
            );
        }
    }

    // Covers: DWN-PROTO-001, DWN-PROTO-002
    #[test]
    fn bounded_subscribe_may_omit_scope() {
        let unscoped = filter(Some("thread/message"), None, None);
        assert!(validate_nested_protocol_path_scope(&unscoped, true).is_ok());
        assert!(validate_nested_protocol_path_scope(&unscoped, false).is_err());
    }

    // Covers: DWN-PROTO-001
    #[test]
    fn nested_scope_error_is_code_free_reason() {
        let error =
            validate_nested_protocol_path_scope(&filter(Some("thread/message"), None, None), false)
                .expect_err("unscoped nested filter must fail");
        assert!(
            error.starts_with("for nested protocol path 'thread/message'"),
            "unexpected error: {error}"
        );
        assert!(
            !error.contains("NestedProtocolPathContextIdInvalid"),
            "method code belongs to the calling handler, not the shared rule: {error}"
        );
    }
}
