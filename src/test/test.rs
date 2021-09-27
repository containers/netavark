//use super::*;

#[cfg(test)]
mod tests {
  use netavark::network;
  #[test]
  // Test setup options loader
  fn test_setup_opts_load(){
    match network::NetworkOptions::load("src/test/config/setupopts.test.json")  {
        Ok(_) => {},
        Err(e) => panic!("{}", e),
    }
  }

  // Test if we can deserialize values correctly
  #[test]
  fn test_setup_opts_assert(){
    match network::NetworkOptions::load("src/test/config/setupopts.test.json") {
        Ok(setupopts) => {assert_eq!(setupopts.container_name, "testcontainer")},
        Err(e) => panic!("{}", e),
    }
  }
}
