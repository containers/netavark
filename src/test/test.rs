//use super::*;

#[cfg(test)]
mod tests {
  use netavark::network;
  #[test]
  // Test setup options loader
  fn test_setup_opts_load(){
    match network::types::NetworkOptions::load("src/test/config/setupopts.test.json")  {
        Ok(_) => {},
        Err(e) => panic!("{}", e),
    }
  }

  // Test if we can deserialize values correctly
  #[test]
  fn test_setup_opts_assert(){
    match network::types::NetworkOptions::load("src/test/config/setupopts.test.json") {
        Ok(setupopts) => {assert_eq!(setupopts.container_name, "testcontainer")},
        Err(e) => panic!("{}", e),
    }
  }

  // Deserialize values correctly
  // Try mutating deserialized struct
  #[test]
  fn test_setup_opts_mutablity(){
    match network::types::NetworkOptions::load("src/test/config/setupopts.test.json") {
        Ok(mut setupopts) => {
            assert_eq!(setupopts.container_name, "testcontainer");
            setupopts.container_name = "mutatedcontainername".to_string();
            assert_eq!(setupopts.container_name, "mutatedcontainername");
        },
        Err(e) => panic!("{}", e),
    }
  }
}
