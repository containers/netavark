use iptables::IPTables;
use log::debug;
use std::error::Error;

// append a rule to chain if it does not exist
// Note: While there is an API provided for this exact thing, the API returns
// an error that is not defined if the rule exists.  This function just returns
// an error if there is a problem.
pub fn append_unique(
    driver: &IPTables,
    table: &str,
    chain: &str,
    rule: &str,
) -> Result<(), Box<dyn Error>> {
    let exists = driver.exists(table, chain, rule)?;
    if exists {
        return Ok(());
    }
    debug_rule_exists(table, chain, rule.to_string());
    if let Err(e) = driver
        .append(table, chain, rule)
        .map(|_| debug_rule_create(table, chain, rule.to_string()))
    {
        bail!(
            "unable to append rule '{}' to table '{}': {}",
            rule,
            table,
            e
        )
    }
    Result::Ok(())
}

// add a chain if it does not exist, else do nothing
pub fn add_chain_unique(
    driver: &IPTables,
    table: &str,
    new_chain: &str,
) -> Result<(), Box<dyn Error>> {
    // Note: while there is an API provided to check if a chain exists in a table
    // by iptables, it, for some reason, is slow.  Instead we just get a list of
    // chains in a table and iterate.  Same is being done in golang implementations
    let exists = chain_exists(driver, table, new_chain)?;
    if exists {
        debug_chain_exists(table, new_chain);
        return Ok(());
    }
    driver
        .new_chain(table, new_chain)
        .map(|_| debug_chain_create(table, new_chain))
}

// returns a bool as to whether the chain exists
fn chain_exists(driver: &IPTables, table: &str, chain: &str) -> Result<bool, Box<dyn Error>> {
    let c = driver.list_chains(table)?;
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
) -> Result<(), Box<dyn Error>> {
    // If the rule is not present, do not error
    let exists = driver.exists(table, chain, rule)?;
    if !exists {
        debug_rule_no_exists(table, chain, rule.to_string());
        return Ok(());
    }
    if let Err(e) = driver.delete(table, chain, rule) {
        bail!(
            "failed to remove rule '{}' from table '{}': {}",
            rule,
            chain,
            e
        )
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
