//! Conversions between the controller's REST/DB model and the gRPC wire types.
//!
//! The reconcile loop hands agents a proto [`mm_proto::Machine`]; agents report back
//! a proto [`mm_proto::State`]. These map to/from [`crate::model`] +
//! [`mm_api_types::State`], whose snake_case names are what the DB stores.
use mm_api_types::State;

use crate::model::Machine;

/// Map an `mm_api_types::State` to its protobuf enum value. The two enums share the
/// same variant order (Created=0 … Destroyed=9), so this is a total, lossless map.
pub fn api_state_to_proto(state: State) -> i32 {
    State::ALL
        .iter()
        .position(|s| *s == state)
        .map(|i| i as i32)
        .unwrap_or(0)
}

/// Map a protobuf state value back to its canonical snake_case name (the form stored
/// in the DB `status.state` field). Returns `None` for an out-of-range value.
pub fn proto_state_name(value: i32) -> Option<&'static str> {
    usize::try_from(value)
        .ok()
        .and_then(|i| State::ALL.get(i))
        .map(|s| s.as_str())
}

/// Build the gRPC `Machine` an agent receives in an `Assignment` from a stored model.
pub fn machine_to_proto(m: &Machine) -> mm_proto::Machine {
    mm_proto::Machine {
        r#ref: Some(mm_proto::MachineRef {
            uid: m.uid.to_string(),
            namespace: m.namespace.clone(),
        }),
        spec: Some(mm_proto::MachineSpec {
            image: m.spec.image.clone(),
            kernel: m.spec.kernel.clone().unwrap_or_default(),
            vcpus: m.spec.vcpus,
            memory_mib: m.spec.memory_mib,
            ssh: m.spec.ssh,
            workload: m.spec.workload.as_ref().map(|w| mm_proto::Workload {
                entrypoint: w.entrypoint.clone(),
                args: w.args.clone(),
                env: w.env.clone().into_iter().collect(),
            }),
            net: Some(mm_proto::Networking {
                mode: "auto".to_string(),
            }),
            running: m.spec.running,
        }),
        status: Some(mm_proto::MachineStatus {
            state: api_state_to_proto(m.status.state),
            ip: m.status.ip.clone().unwrap_or_default(),
            health: m.status.health.clone(),
            host_id: m.host_id.clone().unwrap_or_default(),
            retry_count: m.status.retry_count,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_roundtrips_through_proto() {
        for s in State::ALL {
            let proto = api_state_to_proto(s);
            assert_eq!(proto_state_name(proto), Some(s.as_str()));
        }
    }

    #[test]
    fn proto_state_matches_contract_values() {
        // Guards against the proto enum and mm_api_types::State drifting out of order.
        assert_eq!(api_state_to_proto(State::Created), 0);
        assert_eq!(api_state_to_proto(State::Running), 3);
        assert_eq!(api_state_to_proto(State::Destroyed), 9);
        assert_eq!(proto_state_name(3), Some("running"));
        assert_eq!(proto_state_name(99), None);
    }
}
