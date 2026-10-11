use std::fs;

use sud0::constants::{
    BROKER_BUS_NAME, BROKER_INVOCATION_INTERFACE, BROKER_MANAGER_INTERFACE,
    BROKER_MANAGER_PATH, EXECUTOR_PATH, POLKIT_RUN_ACTION,
};
use sud0::{InvocationStatusWire, RunWire, StdioWire, WindowSize};
use zbus::zvariant::Type;

fn asset(path: &str) -> String {
    fs::read_to_string(format!("{}/{}", env!("CARGO_MANIFEST_DIR"), path)).unwrap()
}

#[test]
fn distribution_assets_match_protocol_constants() {
    let policy = asset("dist/polkit/io.github.passcod.sud0.policy");
    assert!(policy.contains(&format!("action id=\"{POLKIT_RUN_ACTION}\"")));
    assert!(!policy.contains("org.freedesktop.policykit.exec.path"));

    let bus_policy = asset("dist/dbus-1/system.d/io.github.passcod.sud0.conf");
    assert!(bus_policy.contains(&format!("allow own=\"{BROKER_BUS_NAME}\"")));
    assert!(bus_policy.contains(&format!("allow send_destination=\"{BROKER_BUS_NAME}\"")));

    let activation = asset("dist/dbus-1/system-services/io.github.passcod.sud0.service");
    assert!(activation.contains(&format!("Name={BROKER_BUS_NAME}")));
    assert!(activation.contains("Exec=/usr/lib/sud0/sud0-broker"));

    let unit = asset("dist/systemd/system/sud0-broker.service");
    assert!(unit.contains(&format!("BusName={BROKER_BUS_NAME}")));
    assert!(unit.contains("ExecStart=/usr/lib/sud0/sud0-broker"));
    assert!(!unit.contains("[Install]"));
    assert_eq!(EXECUTOR_PATH, "/usr/lib/sud0/sud0-exec");
}

#[test]
fn introspection_fixture_matches_exported_types() {
    let xml = asset("docs/dbus-api.xml");
    assert!(xml.contains(&format!("node name=\"{BROKER_MANAGER_PATH}\"")));
    assert!(xml.contains(&format!("interface name=\"{BROKER_MANAGER_INTERFACE}\"")));
    assert!(xml.contains(&format!("interface name=\"{BROKER_INVOCATION_INTERFACE}\"")));
    for signature in [
        RunWire::SIGNATURE,
        StdioWire::SIGNATURE,
        WindowSize::SIGNATURE,
        InvocationStatusWire::SIGNATURE,
    ] {
        assert!(xml.contains(signature.as_str()), "missing signature {signature}");
    }
}
