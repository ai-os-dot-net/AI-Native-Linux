use crate::enums::{EcosystemRuntimeAdapter, IsolationLevel};

/// Map an ecosystem runtime adapter to the appropriate isolation level.
pub fn map_runtime_to_isolation(runtime: EcosystemRuntimeAdapter) -> IsolationLevel {
    match runtime {
        EcosystemRuntimeAdapter::RuntimeWasmNative => IsolationLevel::Wasm,
        EcosystemRuntimeAdapter::RuntimeEbpfNative => IsolationLevel::ProcessSandbox,
        EcosystemRuntimeAdapter::RuntimeDeno => IsolationLevel::ProcessSandbox,
        EcosystemRuntimeAdapter::RuntimeBun => IsolationLevel::ProcessSandbox,
        EcosystemRuntimeAdapter::RuntimePythonNative => IsolationLevel::ProcessSandbox,
    }
}

/// Returns `true` if the runtime is allowed for AI workloads.
///
/// eBPF native runtime is excluded from AI workloads per INV-025
/// (AI-only `DROP_ONLY` policy). AI can use WasmNative, Deno, Bun, and
/// PythonNative.
pub fn is_ai_allowed_runtime(runtime: EcosystemRuntimeAdapter) -> bool {
    runtime != EcosystemRuntimeAdapter::RuntimeEbpfNative
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    reason = "panic-on-failure is the idiomatic test signal"
)]
mod tests {
    use super::*;

    #[test]
    fn wasm_maps_to_wasm_isolation() {
        assert_eq!(
            map_runtime_to_isolation(EcosystemRuntimeAdapter::RuntimeWasmNative),
            IsolationLevel::Wasm
        );
    }

    #[test]
    fn ebpf_maps_to_process_sandbox() {
        assert_eq!(
            map_runtime_to_isolation(EcosystemRuntimeAdapter::RuntimeEbpfNative),
            IsolationLevel::ProcessSandbox
        );
    }

    #[test]
    fn deno_maps_to_process_sandbox() {
        assert_eq!(
            map_runtime_to_isolation(EcosystemRuntimeAdapter::RuntimeDeno),
            IsolationLevel::ProcessSandbox
        );
    }

    #[test]
    fn bun_maps_to_process_sandbox() {
        assert_eq!(
            map_runtime_to_isolation(EcosystemRuntimeAdapter::RuntimeBun),
            IsolationLevel::ProcessSandbox
        );
    }

    #[test]
    fn python_native_maps_to_process_sandbox() {
        assert_eq!(
            map_runtime_to_isolation(EcosystemRuntimeAdapter::RuntimePythonNative),
            IsolationLevel::ProcessSandbox
        );
    }

    #[test]
    fn ebpf_is_not_ai_allowed() {
        assert!(!is_ai_allowed_runtime(
            EcosystemRuntimeAdapter::RuntimeEbpfNative
        ));
    }

    #[test]
    fn wasm_is_ai_allowed() {
        assert!(is_ai_allowed_runtime(
            EcosystemRuntimeAdapter::RuntimeWasmNative
        ));
    }

    #[test]
    fn deno_is_ai_allowed() {
        assert!(is_ai_allowed_runtime(EcosystemRuntimeAdapter::RuntimeDeno));
    }

    #[test]
    fn bun_is_ai_allowed() {
        assert!(is_ai_allowed_runtime(EcosystemRuntimeAdapter::RuntimeBun));
    }

    #[test]
    fn python_native_is_ai_allowed() {
        assert!(is_ai_allowed_runtime(
            EcosystemRuntimeAdapter::RuntimePythonNative
        ));
    }
}
