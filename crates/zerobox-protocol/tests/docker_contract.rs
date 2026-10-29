use std::str::FromStr;

use zerobox_protocol::docker::{
    DockerAccessPolicy, DockerOperation, DockerTargetGrant, DockerTargetSelector, UnixSocketPath,
};

#[test]
fn permanent_exec_exception_round_trips_without_changing_default_grants() {
    let value = serde_json::json!({"selector":{"type":"container-name","name":"api"},"operations":["exec"],"allowUnsafeTarget":true,"allowUnsafeExec":true});
    let grant: DockerTargetGrant = serde_json::from_value(value.clone()).unwrap();
    assert_eq!(serde_json::to_value(grant).unwrap(), value);
    let default = serde_json::json!({"selector":{"type":"container-name","name":"api"},"operations":["exec"],"allowUnsafeTarget":true});
    let grant: DockerTargetGrant = serde_json::from_value(default.clone()).unwrap();
    assert_eq!(serde_json::to_value(grant).unwrap(), default);
}

#[test]
fn docker_contract_round_trips_targeted_grants() {
    let policy = DockerAccessPolicy::Targeted {
        engine_info: None,
        endpoint: UnixSocketPath::from_str("unix:///var/run/docker.sock").unwrap(),
        targets: vec![DockerTargetGrant {
            selector: DockerTargetSelector::ComposeService {
                project: "app".to_string(),
                service: "api".to_string(),
            },
            operations: None,
            allow_unsafe_target: false,
            allow_unsafe_exec: None,
        }],
    };

    let encoded = serde_json::to_value(&policy).unwrap();
    assert_eq!(encoded["mode"], "targeted");
    assert_eq!(encoded["endpoint"], "unix:///var/run/docker.sock");
    assert_eq!(encoded["targets"][0]["selector"]["type"], "compose-service");
    assert_eq!(
        policy.targets().unwrap()[0].effective_operations(),
        DockerOperation::ALL
    );
    assert_eq!(
        serde_json::from_value::<DockerAccessPolicy>(encoded).unwrap(),
        policy
    );
}

#[test]
fn docker_endpoint_accepts_only_absolute_local_unix_sockets() {
    assert!(UnixSocketPath::from_str("unix:///run/user/1000/docker.sock").is_ok());
    assert!(UnixSocketPath::from_str("/var/run/docker.sock").is_ok());
    assert!(UnixSocketPath::from_str("tcp://127.0.0.1:2375").is_err());
    assert!(UnixSocketPath::from_str("ssh://docker@example.test").is_err());
    assert!(UnixSocketPath::from_str("relative/docker.sock").is_err());
}

#[test]
fn container_name_selector_has_an_explicit_json_field() {
    let policy = DockerAccessPolicy::Targeted {
        engine_info: None,
        endpoint: UnixSocketPath::default(),
        targets: vec![DockerTargetGrant {
            selector: DockerTargetSelector::ContainerName {
                name: "api".to_string(),
            },
            operations: Some(vec![DockerOperation::Inspect]),
            allow_unsafe_target: false,
            allow_unsafe_exec: None,
        }],
    };

    let encoded = serde_json::to_value(&policy).unwrap();
    assert_eq!(
        encoded["targets"][0]["selector"],
        serde_json::json!({ "type": "container-name", "name": "api" })
    );
    assert_eq!(
        serde_json::from_value::<DockerAccessPolicy>(encoded).unwrap(),
        policy
    );
}

#[test]
fn ephemeral_container_selector_round_trips_an_exact_id_and_expiry() {
    let encoded = serde_json::json!({
        "mode": "targeted",
        "endpoint": "unix:///var/run/docker.sock",
        "targets": [{
            "selector": {
                "type": "ephemeral-container",
                "id": "0123456789abcdef",
                "unsafeExecExpiresAtMs": 4_102_444_800_000_u64
            },
            "operations": ["exec"],
            "allowUnsafeTarget": true
        }]
    });

    let policy = serde_json::from_value::<DockerAccessPolicy>(encoded.clone()).unwrap();
    assert_eq!(serde_json::to_value(policy).unwrap(), encoded);
}

#[test]
fn engine_information_is_optional_and_preserved_in_the_wire_contract() {
    let base =
        serde_json::json!({"mode":"targeted","endpoint":"unix:///run/docker.sock","targets":[]});
    let policy: DockerAccessPolicy = serde_json::from_value(base.clone()).unwrap();
    assert!(
        serde_json::to_value(policy)
            .unwrap()
            .get("engineInfo")
            .is_none()
    );
    let mut enabled = base.clone();
    enabled["engineInfo"] = serde_json::json!(true);
    let policy: DockerAccessPolicy = serde_json::from_value(enabled.clone()).unwrap();
    assert_eq!(serde_json::to_value(policy).unwrap(), enabled);
    enabled["engineInfo"] = serde_json::json!("true");
    assert!(serde_json::from_value::<DockerAccessPolicy>(enabled).is_err());
}
