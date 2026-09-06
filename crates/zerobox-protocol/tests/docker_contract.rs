use std::str::FromStr;

use zerobox_protocol::docker::{
    DockerAccessPolicy, DockerOperation, DockerTargetGrant, DockerTargetSelector, UnixSocketPath,
};

#[test]
fn docker_contract_round_trips_targeted_grants() {
    let policy = DockerAccessPolicy::Targeted {
        endpoint: UnixSocketPath::from_str("unix:///var/run/docker.sock").unwrap(),
        targets: vec![DockerTargetGrant {
            selector: DockerTargetSelector::ComposeService {
                project: "app".to_string(),
                service: "api".to_string(),
            },
            operations: None,
            allow_unsafe_target: false,
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
        endpoint: UnixSocketPath::default(),
        targets: vec![DockerTargetGrant {
            selector: DockerTargetSelector::ContainerName {
                name: "api".to_string(),
            },
            operations: Some(vec![DockerOperation::Inspect]),
            allow_unsafe_target: false,
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
