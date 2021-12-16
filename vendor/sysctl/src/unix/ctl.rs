// unix/ctl.rs

use super::funcs::*;
use ctl_error::SysctlError;
use ctl_flags::CtlFlags;
use ctl_info::CtlInfo;
use ctl_type::CtlType;
use ctl_value::CtlValue;
use std::str::FromStr;
use traits::Sysctl;

/// This struct represents a system control.
#[derive(Debug, Clone, PartialEq)]
pub struct Ctl {
    pub oid: Vec<libc::c_int>,
}

impl std::str::FromStr for Ctl {
    type Err = SysctlError;

    #[cfg_attr(feature = "cargo-clippy", allow(clippy::redundant_field_names))]
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let oid = name2oid(s)?;

        Ok(Ctl { oid: oid })
    }
}

impl Sysctl for Ctl {
    fn new(name: &str) -> Result<Self, SysctlError> {
        Ctl::from_str(name)
    }

    fn name(&self) -> Result<String, SysctlError> {
        oid2name(&self.oid)
    }

    fn value_type(&self) -> Result<CtlType, SysctlError> {
        let info = oidfmt(&self.oid)?;
        Ok(info.ctl_type)
    }

    #[cfg(not(target_os = "macos"))]
    fn description(&self) -> Result<String, SysctlError> {
        oid2description(&self.oid)
    }

    #[cfg(target_os = "macos")]
    fn description(&self) -> Result<String, SysctlError> {
        Ok("[N/A]".to_string())
    }

    #[cfg(not(target_os = "macos"))]
    fn value(&self) -> Result<CtlValue, SysctlError> {
        value_oid(&self.oid)
    }

    #[cfg(target_os = "macos")]
    fn value(&self) -> Result<CtlValue, SysctlError> {
        let mut oid = self.oid.clone();
        value_oid(&mut oid)
    }

    #[cfg(not(target_os = "macos"))]
    fn value_as<T>(&self) -> Result<Box<T>, SysctlError> {
        value_oid_as::<T>(&self.oid)
    }

    fn value_string(&self) -> Result<String, SysctlError> {
        self.value().map(|v| format!("{}", v))
    }

    #[cfg(target_os = "macos")]
    fn value_as<T>(&self) -> Result<Box<T>, SysctlError> {
        let mut oid = self.oid.clone();
        value_oid_as::<T>(&mut oid)
    }

    #[cfg(not(target_os = "macos"))]
    fn set_value(&self, value: CtlValue) -> Result<CtlValue, SysctlError> {
        set_oid_value(&self.oid, value)
    }

    #[cfg(target_os = "macos")]
    fn set_value(&self, value: CtlValue) -> Result<CtlValue, SysctlError> {
        let mut oid = self.oid.clone();
        set_oid_value(&mut oid, value)
    }

    #[cfg(not(target_os = "macos"))]
    fn set_value_string(&self, value: &str) -> Result<String, SysctlError> {
        let ctl_type = self.value_type()?;
        let _ = match ctl_type {
            CtlType::String => set_oid_value(&self.oid, CtlValue::String(value.to_owned())),
            CtlType::Uint => set_oid_value(
                &self.oid,
                CtlValue::Uint(value.parse::<u32>().map_err(|_| SysctlError::ParseError)?),
            ),
            CtlType::Int => set_oid_value(
                &self.oid,
                CtlValue::Int(value.parse::<i32>().map_err(|_| SysctlError::ParseError)?),
            ),
            CtlType::Ulong => set_oid_value(
                &self.oid,
                CtlValue::Ulong(value.parse::<u64>().map_err(|_| SysctlError::ParseError)?),
            ),
            CtlType::U8 => set_oid_value(
                &self.oid,
                CtlValue::U8(value.parse::<u8>().map_err(|_| SysctlError::ParseError)?),
            ),
            _ => Err(SysctlError::MissingImplementation),
        }?;
        self.value_string()
    }

    #[cfg(target_os = "macos")]
    fn set_value_string(&self, value: &str) -> Result<String, SysctlError> {
        let ctl_type = self.value_type()?;
        let mut oid = self.oid.clone();
        let _ = match ctl_type {
            CtlType::String => set_oid_value(&mut oid, CtlValue::String(value.to_owned())),
            CtlType::Uint => set_oid_value(
                &mut oid,
                CtlValue::Uint(value.parse::<u32>().map_err(|_| SysctlError::ParseError)?),
            ),
            CtlType::Int => set_oid_value(
                &mut oid,
                CtlValue::Int(value.parse::<i32>().map_err(|_| SysctlError::ParseError)?),
            ),
            CtlType::Ulong => set_oid_value(
                &mut oid,
                CtlValue::Ulong(value.parse::<u64>().map_err(|_| SysctlError::ParseError)?),
            ),
            CtlType::U8 => set_oid_value(
                &mut oid,
                CtlValue::U8(value.parse::<u8>().map_err(|_| SysctlError::ParseError)?),
            ),
            _ => Err(SysctlError::MissingImplementation),
        }?;
        self.value_string()
    }

    fn flags(&self) -> Result<CtlFlags, SysctlError> {
        Ok(self.info()?.flags())
    }

    fn info(&self) -> Result<CtlInfo, SysctlError> {
        oidfmt(&self.oid)
    }
}

#[cfg(test)]
mod tests {
    use crate::Sysctl;

    #[test]
    fn ctl_new() {
        let _ = super::Ctl::new("kern.ostype").expect("Ctl::new");
    }

    #[test]
    fn ctl_description() {
        let ctl = super::Ctl::new("kern.ostype").expect("Ctl::new");

        let descp = ctl.description();
        assert!(descp.is_ok());

        let descp = descp.unwrap();

        #[cfg(target_os = "freebsd")]
        assert_eq!(descp, "Operating system type");

        #[cfg(any(target_os = "macos", target_os = "linux"))]
        assert_eq!(descp, "[N/A]");
    }
}

#[cfg(all(test, target_os = "freebsd"))]
mod tests_freebsd {}
