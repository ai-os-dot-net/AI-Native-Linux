//! Contract test for the committed KDE QML component artifacts (S7.3 §8.1).
//!
//! The KDE renderer consumes the shared ComponentRecipes through generated QML:
//! `AiosTokens.qml` (the token singleton from `to_qml_properties`) and
//! `AiosComponents.qml` (the 13-component library that binds them). This test
//! is Qt-free — it proves the artifacts exist and honour the binding contract,
//! so CI without a Qt runtime still guards them. Live pixel rendering is proven
//! separately with `qml6` (see the crate's render evidence).

use std::fs;

fn qml(name: &str) -> String {
    fs::read_to_string(format!("qml/generated/{name}"))
        .unwrap_or_else(|e| panic!("missing qml/generated/{name}: {e}"))
}

#[test]
fn tokens_singleton_is_the_generated_source() {
    let t = qml("AiosTokens.qml");
    assert!(t.contains("pragma Singleton"), "AiosTokens must be a singleton");
    // The constitutional colour roles the components bind must be present.
    for role in [
        "colorActionAi",
        "colorActionHuman",
        "colorRecovery",
        "colorTrustVerified",
        "colorTrustDenied",
        "colorEvidencePermanent",
    ] {
        assert!(t.contains(role), "AiosTokens missing {role}");
    }
}

#[test]
fn components_bind_the_tokens_and_cover_the_library() {
    let c = qml("AiosComponents.qml");
    assert!(c.contains("import aios.generated"), "must import the token module");
    assert!(c.contains("AiosTokens.color"), "components must bind AiosTokens colours, not literals");
    // No hand-picked hex — every colour comes from a token.
    assert!(!c.contains("\"#"), "AiosComponents must not contain literal hex colours");
    // The 13 recipes are all present (one ListElement each).
    assert_eq!(
        c.matches("ListElement {").count(),
        13,
        "the KDE component library must render all 13 recipes"
    );
    // The AI/human distinction survives: AI rows carry italic, and the AI and
    // human colour roles are both bound.
    assert!(c.contains("colorActionAi"));
    assert!(c.contains("colorActionHuman"));
    assert!(c.contains("italic:true"));
}

#[test]
fn qmldir_registers_the_singleton() {
    let d = qml("qmldir");
    assert!(d.contains("singleton AiosTokens"), "qmldir must register the AiosTokens singleton");
}
