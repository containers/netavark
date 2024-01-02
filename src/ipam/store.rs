use rusqlite::{Connection, Result};
use std::net::IpAddr;
use std::path::Path;

const NETAVARK_IPAM_DATABASE: &str = "netavark_ipam.sqlite";

#[derive(Debug)]
pub struct IpamEntry {
    pub id: i32,
    pub ip: IpAddr,
    pub network: String,
    pub ctr_id: String,
}

pub fn get_ipamdb_connection(base: &str) -> Result<Connection, std::io::Error> {
    let data_path = Path::new(&base).join("..").join(NETAVARK_IPAM_DATABASE);
    let result = match Connection::open(data_path) {
        Ok(conn) => conn,
        Err(e) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("unable to open ipam database: {e}"),
            ));
        }
    };
    return Ok(result);
}

pub fn create_ipam_table(conn: &Connection) {
    _ = conn.execute(
        "CREATE TABLE ipam (
            id       INTEGER PRIMARY KEY,
            ip       BLOB,
            network  VARCHAR,
            ctr_id   VARCHAR
        )",
        (),
    );
}

// All ip by network ordered by id, so first entry is the last ip address
pub fn get_ipam_entry_by_network(conn: &Connection, network: String) -> Result<Vec<IpamEntry>> {
    let mut stmt = conn.prepare("SELECT * FROM ipam WHERE network = ?1 ORDER BY id DESC")?;
    let ip_enteries = stmt.query_map([network], |row| {
        let ip_raw: Vec<u8> = row.get(1)?;
        let ipaddr: IpAddr;
        if ip_raw.len() == 4 {
            ipaddr = IpAddr::from(<Vec<u8> as TryInto<[u8; 4]>>::try_into(ip_raw).unwrap());
        } else {
            ipaddr = IpAddr::from(<Vec<u8> as TryInto<[u8; 16]>>::try_into(ip_raw).unwrap());
        }
        Ok(IpamEntry {
            id: row.get(0)?,
            ip: ipaddr,
            network: row.get(2)?,
            ctr_id: row.get(3)?,
        })
    })?;
    let mut result: Vec<IpamEntry> = Vec::new();
    for entry in ip_enteries {
        match entry {
            Ok(entry) => result.push(entry),
            _ => {}
        }
    }
    return Ok(result);
}

// All ip by network ordered by id, so first entry is the last ip address
pub fn get_ipam_entry_by_ip(conn: &Connection, ip: IpAddr) -> Result<Vec<IpamEntry>> {
    let mut stmt = conn.prepare("SELECT * FROM ipam WHERE ip = ?1 ORDER BY id DESC")?;
    match ip {
        IpAddr::V4(ip) => {
            let ip_enteries = stmt.query_map([ip.octets()], |row| {
                let ip_raw: Vec<u8> = row.get(1)?;
                let ipaddr: IpAddr;
                if ip_raw.len() == 4 {
                    ipaddr = IpAddr::from(<Vec<u8> as TryInto<[u8; 4]>>::try_into(ip_raw).unwrap());
                } else {
                    ipaddr =
                        IpAddr::from(<Vec<u8> as TryInto<[u8; 16]>>::try_into(ip_raw).unwrap());
                }
                Ok(IpamEntry {
                    id: row.get(0)?,
                    ip: ipaddr,
                    network: row.get(2)?,
                    ctr_id: row.get(3)?,
                })
            })?;
            let mut result: Vec<IpamEntry> = Vec::new();
            for entry in ip_enteries {
                match entry {
                    Ok(entry) => result.push(entry),
                    _ => {}
                }
            }
            return Ok(result);
        }
        IpAddr::V6(ip) => {
            let ip_enteries = stmt.query_map([ip.octets()], |row| {
                let ip_raw: Vec<u8> = row.get(1)?;
                let ipaddr: IpAddr;
                if ip_raw.len() == 4 {
                    ipaddr = IpAddr::from(<Vec<u8> as TryInto<[u8; 4]>>::try_into(ip_raw).unwrap());
                } else {
                    ipaddr =
                        IpAddr::from(<Vec<u8> as TryInto<[u8; 16]>>::try_into(ip_raw).unwrap());
                }
                Ok(IpamEntry {
                    id: row.get(0)?,
                    ip: ipaddr,
                    network: row.get(2)?,
                    ctr_id: row.get(3)?,
                })
            })?;
            let mut result: Vec<IpamEntry> = Vec::new();
            for entry in ip_enteries {
                match entry {
                    Ok(entry) => result.push(entry),
                    _ => {}
                }
            }
            return Ok(result);
        }
    }
}

pub fn insert_ipam_entry(conn: &Connection, entry: IpamEntry) -> Result<usize> {
    match entry.ip {
        IpAddr::V4(ip) => {
            return conn.execute(
                "INSERT INTO ipam (ip, network, ctr_id) VALUES (?1, ?2, ?3)",
                (ip.octets(), &entry.network, &entry.ctr_id),
            );
        }
        IpAddr::V6(ip) => {
            return conn.execute(
                "INSERT INTO ipam (ip, network, ctr_id) VALUES (?1, ?2, ?3)",
                (ip.octets(), &entry.network, &entry.ctr_id),
            );
        }
    }
}

pub fn delete_ipam_entry_by_ip(conn: &Connection, ip: IpAddr) -> Result<usize> {
    match ip {
        IpAddr::V4(ip) => {
            return conn.execute("DELETE FROM ipam WHERE ip = ?1", [ip.octets()]);
        }
        IpAddr::V6(ip) => {
            return conn.execute("DELETE FROM ipam WHERE ip = ?1", [ip.octets()]);
        }
    }
}

pub fn delete_ipam_entry_by_network(conn: &Connection, network: String) -> Result<usize> {
    return conn.execute("DELETE FROM ipam WHERE network = ?1", [network.as_str()]);
}

pub fn delete_ipam_entry_by_ctr(conn: &Connection, id: String) -> Result<usize> {
    return conn.execute("DELETE FROM ipam WHERE ctr_id = ?1", [id.as_str()]);
}

pub fn get_all_ipam_entry(conn: &Connection) -> Result<Vec<IpamEntry>> {
    let mut stmt = conn.prepare("SELECT * FROM ipam")?;
    let ip_enteries = stmt.query_map([], |row| {
        let ip_raw: Vec<u8> = row.get(1)?;
        let ipaddr: IpAddr;
        if ip_raw.len() == 4 {
            ipaddr = IpAddr::from(<Vec<u8> as TryInto<[u8; 4]>>::try_into(ip_raw).unwrap());
        } else {
            ipaddr = IpAddr::from(<Vec<u8> as TryInto<[u8; 16]>>::try_into(ip_raw).unwrap());
        }
        Ok(IpamEntry {
            id: row.get(0)?,
            ip: ipaddr,
            network: row.get(2)?,
            ctr_id: row.get(3)?,
        })
    })?;
    let mut result: Vec<IpamEntry> = Vec::new();
    for entry in ip_enteries {
        match entry {
            Ok(entry) => result.push(entry),
            _ => {}
        }
    }
    return Ok(result);
}
