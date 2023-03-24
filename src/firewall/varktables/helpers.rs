use crate::error::{NetavarkError, NetavarkResult};
use iptables::IPTables;
use log::debug;

// append a rule to chain if it does not exist
// Note: While there is an API provided for this exact thing, the API returns
// an error that is not defined if the rule exists.  This function just returns
// an error if there is a problem.
pub fn append_unique(
    driver: &IPTables,
    table: &str,
    chain: &str,
    rule: &str,
) -> NetavarkResult<()> {
    let exists = match driver.exists(table, chain, rule) {
        Ok(b) => b,
        Err(e) => return Err(NetavarkError::Message(e.to_string())),
    };
    if exists {
        debug_rule_exists(table, chain, rule.to_string());
        return Ok(());
    }
    if let Err(e) = driver
        .append(table, chain, rule)
        .map(|_| debug_rule_create(table, chain, rule.to_string()))
    {
        return Err(NetavarkError::Message(format!(
            "unable to append rule '{}' to table '{}': {}",
            rule, table, e,
        )));
    }
    Result::Ok(())
}

// add a chain if it does not exist, else do nothing
pub fn add_chain_unique(driver: &IPTables, table: &str, new_chain: &str) -> NetavarkResult<()> {
    // Note: while there is an API provided to check if a chain exists in a table
    // by iptables, it, for some reason, is slow.  Instead we just get a list of
    // chains in a table and iterate.  Same is being done in golang implementations
    let exists = chain_exists(driver, table, new_chain)?;
    if exists {
        debug_chain_exists(table, new_chain);
        return Ok(());
    }
    match driver
        .new_chain(table, new_chain)
        .map(|_| debug_chain_create(table, new_chain))
    {
        Ok(_) => Ok(()),
        Err(e) => Err(NetavarkError::Message(e.to_string())),
    }
}

// returns a bool as to whether the chain exists
fn chain_exists(driver: &IPTables, table: &str, chain: &str) -> NetavarkResult<bool> {
    let c = match driver.list_chains(table) {
        Ok(b) => b,
        Err(e) => return Err(NetavarkError::Message(e.to_string())),
    };
    if c.iter().any(|i| i == chain) {
        debug_chain_exists(table, chain);
        return serde::__private::Result::Ok(true);
    }
    serde::__private::Result::Ok(false)
}

pub fn remove_if_rule_exists(
    driver: &IPTables,
    table: &str,
    chain: &str,
    rule: &str,
) -> NetavarkResult<()> {
    // If the rule is not present, do not error
    let exists = match driver.exists(table, chain, rule) {
        Ok(b) => b,
        Err(e) => return Err(NetavarkError::Message(e.to_string())),
    };
    if !exists {
        debug_rule_no_exists(table, chain, rule.to_string());
        return Ok(());
    }
    if let Err(e) = driver.delete(table, chain, rule) {
        return Err(NetavarkError::Message(format!(
            "failed to remove rule '{}' from table '{}': {}",
            rule, chain, e
        )));
    }
    Result::Ok(())
}

fn debug_chain_create(table: &str, chain: &str) {
    debug!("chain {} created on table {}", chain, table);
}

fn debug_chain_exists(table: &str, chain: &str) {
    debug!("chain {} exists on table {}", chain, table);
}

pub fn debug_rule_create(table: &str, chain: &str, rule: String) {
    debug!(
        "rule {} created on table {} and chain {}",
        rule, table, chain
    );
}

fn debug_rule_exists(table: &str, chain: &str, rule: String) {
    debug!(
        "rule {} exists on table {} and chain {}",
        rule, table, chain
    );
}

fn debug_rule_no_exists(table: &str, chain: &str, rule: String) {
    debug!(
        "no rule {} exists on table {} and chain {}",
        rule, table, chain
    );
}
