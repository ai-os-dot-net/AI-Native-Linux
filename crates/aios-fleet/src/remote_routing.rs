use crate::enums::{RemoteRoutingClass, RemoteRoutingReason};

#[derive(Debug, Clone)]
pub struct RemoteWorkloadRouting {
    pub routing_id: String,
    pub workload_ref: String,
    pub origin_host: String,
    pub target_host: String,
    pub reason: RemoteRoutingReason,
    pub routing_class: RemoteRoutingClass,
}

impl RemoteWorkloadRouting {
    #[must_use]
    pub fn new(
        routing_id: String,
        workload_ref: String,
        origin_host: String,
        target_host: String,
        reason: RemoteRoutingReason,
        routing_class: RemoteRoutingClass,
    ) -> Self {
        Self {
            routing_id,
            workload_ref,
            origin_host,
            target_host,
            reason,
            routing_class,
        }
    }

    #[must_use]
    pub fn requires_target_approval(&self) -> bool {
        true
    }

    #[must_use]
    pub fn can_route(&self) -> bool {
        self.routing_class != RemoteRoutingClass::BlockedRoute
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mk_routing(class: RemoteRoutingClass) -> RemoteWorkloadRouting {
        RemoteWorkloadRouting::new(
            "rte_01".into(),
            "wl_ref_01".into(),
            "host_a".into(),
            "host_b".into(),
            RemoteRoutingReason::CapacityOffload,
            class,
        )
    }

    #[test]
    fn target_approval_always_required() {
        let r = mk_routing(RemoteRoutingClass::SandboxedCapsule);
        assert!(r.requires_target_approval());
    }

    #[test]
    fn sandboxed_capsule_can_route() {
        let r = mk_routing(RemoteRoutingClass::SandboxedCapsule);
        assert!(r.can_route());
    }

    #[test]
    fn micro_vm_job_can_route() {
        let r = mk_routing(RemoteRoutingClass::MicroVmJob);
        assert!(r.can_route());
    }

    #[test]
    fn driver_lab_job_can_route() {
        let r = mk_routing(RemoteRoutingClass::DriverLabJob);
        assert!(r.can_route());
    }

    #[test]
    fn kernel_build_job_can_route() {
        let r = mk_routing(RemoteRoutingClass::KernelBuildJob);
        assert!(r.can_route());
    }

    #[test]
    fn blocked_route_cannot_route() {
        let r = mk_routing(RemoteRoutingClass::BlockedRoute);
        assert!(!r.can_route());
    }

    #[test]
    fn all_non_blocked_classes_can_route() {
        use strum::IntoEnumIterator;
        for class in RemoteRoutingClass::iter() {
            let r = mk_routing(class);
            if class == RemoteRoutingClass::BlockedRoute {
                assert!(!r.can_route(), "BlockedRoute should not be routable");
            } else {
                assert!(r.can_route(), "{class:?} should be routable");
            }
        }
    }
}
