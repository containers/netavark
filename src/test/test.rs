//use super::*;

#[cfg(test)]
mod tests {
    use std::ffi::OsString;

    use netavark::network;
    #[test]
    // Test setup options loader
    fn test_setup_opts_load_map() {
        let a = network::types::NetworkOptions::load(Some(OsString::from(
            "src/test/config/setupopts.test.json",
        )))
        .unwrap();
        assert_eq!(a.networks.len(), 1);
    }

    #[test]
    fn test_setup_opts_load_vec() {
        let a = network::types::NetworkOptions::load(Some(OsString::from(
            "src/test/config/setupopts2.test.json",
        )))
        .unwrap();
        assert_eq!(a.networks.len(), 1);
    }

    #[test]
    // Test setup options loader
    fn test_load_two_networks() {
        let array = network::types::NetworkOptions::load(Some(OsString::from(
            "src/test/config/twoNetworks-array.json",
        )))
        .unwrap();
        assert_eq!(array.networks.len(), 2);
        assert_eq!(array.networks[0].name, "podman1");
        assert_eq!(array.networks[0].opts.interface_name, "eth0");
        assert_eq!(array.networks[1].name, "podman2");
        assert_eq!(array.networks[1].opts.interface_name, "eth1");

        let map = network::types::NetworkOptions::load(Some(OsString::from(
            "src/test/config/twoNetworks-map.json",
        )))
        .unwrap();

        // both the parsed array or map version should result in the same value
        assert_eq!(array, map);
    }

    // Test if we can deserialize values correctly
    #[test]
    fn test_setup_opts_assert() {
        match network::types::NetworkOptions::load(Some(OsString::from(
            "src/test/config/setupopts.test.json",
        ))) {
            Ok(setupopts) => {
                assert_eq!(setupopts.container_name, "testcontainer")
            }
            Err(e) => panic!("{}", e),
        }
    }

    // Deserialize values correctly
    // Try mutating deserialized struct
    #[test]
    fn test_setup_opts_mutability() {
        match network::types::NetworkOptions::load(Some(OsString::from(
            "src/test/config/setupopts.test.json",
        ))) {
            Ok(mut setupopts) => {
                assert_eq!(setupopts.container_name, "testcontainer");
                setupopts.container_name = "mutatedcontainername".to_string();
                assert_eq!(setupopts.container_name, "mutatedcontainername");
            }
            Err(e) => panic!("{}", e),
        }
    }

    // Test commands::setup::ns_checks works correctly
    #[test]
    fn test_ns_checks() {
        assert!(network::validation::ns_checks("src/test/config/setupopts.test.json").is_ok());
    }
}
