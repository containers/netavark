use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;

pub fn next_ip(ip: &IpAddr) -> Option<IpAddr> {
    match ip {
        IpAddr::V4(ipv4) => {
            let ip = ipv4.octets();
            let ip_num = u32::from_be_bytes(ip);
            let (ip_num, overflow) = ip_num.overflowing_add(1);
            if overflow {
                return None;
            }
            Some(IpAddr::V4(Ipv4Addr::from(ip_num.to_be_bytes())))
        }
        IpAddr::V6(ipv6) => {
            let ip = ipv6.octets();
            let ip_num = u128::from_be_bytes(ip);
            let (ip_num, overflow) = ip_num.overflowing_add(1);
            if overflow {
                return None;
            }
            Some(IpAddr::V6(Ipv6Addr::from(ip_num.to_be_bytes())))
        }
    }
}

pub fn prev_ip(ip: &IpAddr) -> Option<IpAddr> {
    match ip {
        IpAddr::V4(ipv4) => {
            let ip = ipv4.octets();
            let ip_num = u32::from_be_bytes(ip);
            let (ip_num, overflow) = ip_num.overflowing_sub(1);
            if overflow {
                return None;
            }
            Some(IpAddr::V4(Ipv4Addr::from(ip_num.to_be_bytes())))
        }
        IpAddr::V6(ipv6) => {
            let ip = ipv6.octets();
            let ip_num = u128::from_be_bytes(ip);
            let (ip_num, overflow) = ip_num.overflowing_sub(1);
            if overflow {
                return None;
            }
            Some(IpAddr::V6(Ipv6Addr::from(ip_num.to_be_bytes())))
        }
    }
}
