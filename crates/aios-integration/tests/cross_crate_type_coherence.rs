//! Cross-crate type coherence tests for the AI-OS.NET 34-crate system.

#![forbid(unsafe_code)]
#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    clippy::doc_markdown,
    clippy::wildcard_imports,
    clippy::similar_names,
    clippy::too_many_lines,
    clippy::unused_imports,
    missing_docs,
    reason = "test code; panic-on-failure is the idiomatic test signal"
)]

use aios_action::ActionPhase;
use aios_capability_runtime::security_profile::SecurityProfile as CapSecurityProfile;
use aios_container::IsolationLevel as ContainerIsolationLevel;
use aios_evidence::{ReceiptBuilder, RecordType, RetentionClass};
use aios_fleet::federated_identity::FederatedSubjectId;
use aios_hardware::gpu::GpuCapabilityClass as HwGpuCapabilityClass;
use aios_network::posture::NetworkPosture as NetNetworkPosture;
use aios_policy::{
    subject::{HydratedSubject, SubjectType},
    ApprovalScope, ApproverClass, Constraints, Decision, EvidenceGrade, NetworkPolicy,
    PolicyBundle, PolicyRule, RuleEffect, RuleScope,
};
use aios_sandbox::gpu::GpuCapabilityClass as SandboxGpuCapabilityClass;
use aios_sandbox::isolation::IsolationKind;
use aios_sandbox::network::NetworkPosture as SandboxNetworkPosture;
use aios_terminal::UserIntentClass;
use aios_waydroid::AndroidGPUClass;
use aios_wine::WineGPUClass;

// Test 1
#[test]
fn test_security_profile_enum_consistent() {
    let cap = CapSecurityProfile::DevRelaxed;
    let json = serde_json::to_string(&cap).unwrap();
    let back: CapSecurityProfile = serde_json::from_str(&json).unwrap();
    assert_eq!(back, cap);
    assert!(CapSecurityProfile::DevRelaxed < CapSecurityProfile::AirgapHigh);
    assert!(CapSecurityProfile::SecureDefault < CapSecurityProfile::StigAligned);
}

// Test 2
#[test]
fn test_evidence_record_type_consistent() {
    let rt = RecordType::ActionReceived;
    let json = serde_json::to_string(&rt).unwrap();
    let back: RecordType = serde_json::from_str(&json).unwrap();
    assert_eq!(back, rt);

    let rc = RetentionClass::Forever;
    let json = serde_json::to_string(&rc).unwrap();
    assert_eq!(json, "\"FOREVER\"");
    let back: RetentionClass = serde_json::from_str(&json).unwrap();
    assert_eq!(back, rc);

    let variants = [
        RecordType::ActionReceived,
        RecordType::ApprovalRequested,
        RecordType::ApprovalGranted,
        RecordType::ApprovalDenied,
    ];
    let names: Vec<String> = variants
        .iter()
        .map(|v| serde_json::to_string(v).unwrap())
        .collect();
    for i in 0..names.len() {
        for j in 0..names.len() {
            if i != j {
                assert_ne!(names[i], names[j]);
            }
        }
    }
}

// Test 3
#[test]
fn test_subject_actor_kind_consistent() {
    let human = SubjectType::Human;
    let agent = SubjectType::Agent;
    assert_ne!(human, agent);
    let json = serde_json::to_string(&human).unwrap();
    assert!(!json.is_empty()); // SubjectType always serializes to a non-empty string

    let subj = HydratedSubject {
        canonical_subject_id: "test".into(),
        subject_type: SubjectType::Human,
        groups: vec![],
        capabilities: vec![],
        session_class: "PUBLIC".into(),
        recovery_mode: false,
        is_ai: false,
    };
    assert_eq!(subj.subject_type, SubjectType::Human);

    let intent = UserIntentClass::AiAssistRequest;
    assert_eq!(
        serde_json::to_string(&intent).unwrap(),
        "\"AI_ASSIST_REQUEST\""
    );
}

// Test 4
#[test]
fn test_closed_enum_serde_roundtrip() {
    let phase = ActionPhase::Pending;
    let json = serde_json::to_string(&phase).unwrap();
    let back: ActionPhase = serde_json::from_str(&json).unwrap();
    assert_eq!(back, phase);

    let effect = RuleEffect::Allow;
    assert_eq!(serde_json::to_string(&effect).unwrap(), "\"ALLOW\"");
    assert_eq!(
        serde_json::from_str::<RuleEffect>("\"ALLOW\"").unwrap(),
        effect
    );

    let dec = Decision::Allow;
    let back: Decision = serde_json::from_str(&serde_json::to_string(&dec).unwrap()).unwrap();
    assert_eq!(back, dec);

    let grade = EvidenceGrade::E5;
    assert_eq!(serde_json::to_string(&grade).unwrap(), "\"E5\"");

    let scope = ApprovalScope::ExactRequestHash;
    let back: ApprovalScope =
        serde_json::from_str(&serde_json::to_string(&scope).unwrap()).unwrap();
    assert_eq!(back, scope);

    let ac = ApproverClass::Human;
    let back: ApproverClass = serde_json::from_str(&serde_json::to_string(&ac).unwrap()).unwrap();
    assert_eq!(back, ac);

    let net = NetworkPolicy::LocalhostOnly;
    assert_eq!(serde_json::to_string(&net).unwrap(), "\"LOCALHOST_ONLY\"");
    let back: NetworkPolicy = serde_json::from_str("\"LOCALHOST_ONLY\"").unwrap();
    assert_eq!(back, net);
}

// Test 5
#[test]
fn test_federated_subject_id_roundtrip() {
    let fed = FederatedSubjectId::new("realm-01".to_string(), "local-u42".to_string());
    let display = fed.to_string();
    assert!(display.contains("realm-01"));
    assert!(display.contains("local-u42"));

    // Parse from display format
    let parts: Vec<&str> = display.splitn(2, ':').collect();
    assert_eq!(parts.len(), 2);
    assert_eq!(parts[0], "realm-01");
    assert_eq!(parts[1], "local-u42");

    let fed2 = FederatedSubjectId::new("realm-02".to_string(), "local-u42".to_string());
    assert_ne!(fed.to_string(), fed2.to_string());
}

// Test 6
#[test]
fn test_policy_bundle_wire_format() {
    let bundle = PolicyBundle {
        bundle_version: "1.0.0".to_string(),
        bundle_id: "bndl_01".to_string(),
        signing_authority: "aios-root".to_string(),
        signature_ed25519: vec![0u8; 64],
        created_at: chrono::Utc::now(),
        rules: vec![PolicyRule {
            rule_id: "rule-001".to_string(),
            reason_code: "test-allow".to_string(),
            subjects: vec!["human_operator".to_string()],
            actions: vec!["read".to_string()],
            conditions: vec![],
            effect: RuleEffect::Allow,
            priority: 100,
            scope: RuleScope::PerSubjectType,
            constraints: Some(Constraints::default()),
            approval: None,
        }],
    };

    let json = serde_json::to_string_pretty(&bundle).unwrap();
    let back: PolicyBundle = serde_json::from_str(&json).unwrap();
    assert_eq!(back.bundle_id, bundle.bundle_id);
    assert_eq!(back.rules.len(), 1);
}

// Test 7
#[test]
fn test_evidence_payload_json_schema() {
    let payload = serde_json::json!({"action_type": "read", "target": "fs", "duration_ms": 42});
    let json_str = serde_json::to_string(&payload).unwrap();
    assert!(json_str.contains("action_type"));

    let receipt = ReceiptBuilder::new(
        RecordType::ActionReceived,
        RetentionClass::Standard24M,
        "test-subject",
    )
    .with_payload(payload)
    .seal(None)
    .unwrap();

    let p = receipt.payload();
    assert!(!p.is_null());
}

// Test 8
#[test]
fn test_isolation_level_mapping() {
    let ns = IsolationKind::NamespaceLocal;
    let json = serde_json::to_string(&ns).unwrap();
    let back: IsolationKind = serde_json::from_str(&json).unwrap();
    assert_eq!(back, ns);

    let c_std = ContainerIsolationLevel::Standard;
    let c_fvm = ContainerIsolationLevel::FullVm;
    assert_ne!(c_std, c_fvm);
    let c_json = serde_json::to_string(&c_std).unwrap();
    assert!(!c_json.is_empty());
}

// Test 9
#[test]
fn test_network_posture_mapping() {
    let sp = SandboxNetworkPosture::DenyAll;
    let sj = serde_json::to_string(&sp).unwrap();
    assert!(!sj.is_empty());
    let back: SandboxNetworkPosture = serde_json::from_str(&sj).unwrap();
    assert_eq!(back, sp);

    let np = NetNetworkPosture::Airgap;
    let nj = serde_json::to_string(&np).unwrap();
    assert!(!nj.is_empty());
    let back: NetNetworkPosture = serde_json::from_str(&nj).unwrap();
    assert_eq!(back, np);
}

// Test 10
#[test]
fn test_gpu_capability_mapping() {
    let sg = SandboxGpuCapabilityClass::GpuPassiveDisplay;
    let sj = serde_json::to_string(&sg).unwrap();
    let back: SandboxGpuCapabilityClass = serde_json::from_str(&sj).unwrap();
    assert_eq!(back, sg);

    let hg = HwGpuCapabilityClass::RenderOnly;
    let hj = serde_json::to_string(&hg).unwrap();
    let back: HwGpuCapabilityClass = serde_json::from_str(&hj).unwrap();
    assert_eq!(back, hg);

    let ag = AndroidGPUClass::Software;
    let aj = serde_json::to_string(&ag).unwrap();
    let back: AndroidGPUClass = serde_json::from_str(&aj).unwrap();
    assert_eq!(back, ag);

    let wg = WineGPUClass::None;
    let wj = serde_json::to_string(&wg).unwrap();
    let back: WineGPUClass = serde_json::from_str(&wj).unwrap();
    assert_eq!(back, wg);
}
