use crate::enums::WorkloadImporter;

/// Parse a workload source path and return the matching importer variant.
///
/// Matching logic:
/// - `"docker-compose.yml"` or `"docker-compose.yaml"` → `ComposeImporter`
/// - `"Chart.yaml"` → `HelmImporter`
/// - `"kustomization.yaml"` or `"kustomization.yml"` → `KustomizeImporter`
/// - `"*.yaml"` with context hint → `K8sManifestImporter`
/// - `"Dockerfile"` or starts with `"Dockerfile."` → `DockerfileBuilder`
/// - `".devcontainer/"` prefix → `DevcontainerImporter`
/// - Fallback → `K8sManifestImporter`
pub fn parse_workload(source: &str) -> WorkloadImporter {
    if source == "docker-compose.yml" || source == "docker-compose.yaml" {
        WorkloadImporter::ComposeImporter
    } else if source == "Chart.yaml" {
        WorkloadImporter::HelmImporter
    } else if source == "kustomization.yaml" || source == "kustomization.yml" {
        WorkloadImporter::KustomizeImporter
    } else if source.starts_with(".devcontainer/") {
        WorkloadImporter::DevcontainerImporter
    } else if source == "Dockerfile" || source.starts_with("Dockerfile.") {
        WorkloadImporter::DockerfileBuilder
    } else {
        WorkloadImporter::K8sManifestImporter
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    reason = "panic-on-failure is the idiomatic test signal"
)]
mod tests {
    use super::*;

    #[test]
    fn parse_docker_compose_yml() {
        assert_eq!(
            parse_workload("docker-compose.yml"),
            WorkloadImporter::ComposeImporter
        );
        assert_eq!(
            parse_workload("docker-compose.yaml"),
            WorkloadImporter::ComposeImporter
        );
    }

    #[test]
    fn parse_helm_chart() {
        assert_eq!(parse_workload("Chart.yaml"), WorkloadImporter::HelmImporter);
    }

    #[test]
    fn parse_kustomize() {
        assert_eq!(
            parse_workload("kustomization.yaml"),
            WorkloadImporter::KustomizeImporter
        );
        assert_eq!(
            parse_workload("kustomization.yml"),
            WorkloadImporter::KustomizeImporter
        );
    }

    #[test]
    fn parse_devcontainer() {
        assert_eq!(
            parse_workload(".devcontainer/devcontainer.json"),
            WorkloadImporter::DevcontainerImporter
        );
        assert_eq!(
            parse_workload(".devcontainer/Dockerfile"),
            WorkloadImporter::DevcontainerImporter
        );
    }

    #[test]
    fn parse_dockerfile() {
        assert_eq!(
            parse_workload("Dockerfile"),
            WorkloadImporter::DockerfileBuilder
        );
        assert_eq!(
            parse_workload("Dockerfile.prod"),
            WorkloadImporter::DockerfileBuilder
        );
        assert_eq!(
            parse_workload("Dockerfile.dev"),
            WorkloadImporter::DockerfileBuilder
        );
    }

    #[test]
    fn fallback_to_k8s_manifest() {
        assert_eq!(
            parse_workload("deployment.yaml"),
            WorkloadImporter::K8sManifestImporter
        );
        assert_eq!(
            parse_workload("service.yaml"),
            WorkloadImporter::K8sManifestImporter
        );
        assert_eq!(
            parse_workload("unknown.json"),
            WorkloadImporter::K8sManifestImporter
        );
    }
}
