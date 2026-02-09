use std::{
    ffi::OsStr,
    io::Read,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

use crate::{
    dns::aardvark::AardvarkEntry,
    error::{ErrorWrap, JsonError, NetavarkError, NetavarkResult},
    wrap,
};

use super::{
    driver::{DriverInfo, NetworkDriver},
    types,
};
use crate::network::netlink::Socket;
use crate::network::netlink_route::NetlinkRoute;

/// Result of plugin execution
pub(crate) enum PluginResult {
    Success(Vec<u8>),
    Error { code: i32, buffer: Vec<u8> },
    Killed,
}

/// Handle plugin error result by deserializing JsonError and formatting error message.
pub(crate) fn handle_plugin_error(
    code: i32,
    buffer: &[u8],
    plugin_name: Option<&OsStr>,
) -> NetavarkError {
    let err: JsonError = match serde_json::from_slice(buffer) {
        Ok(e) => e,
        Err(e) => {
            return NetavarkError::msg(format!(
                "plugin {:?} failed with exit code {}, and failed to parse error message: {}",
                plugin_name.unwrap_or_default(),
                code,
                e
            ));
        }
    };

    if let Some(name) = plugin_name {
        NetavarkError::msg(format!(
            "plugin {:?} failed with exit code {}, message: {}",
            name, code, err.error
        ))
    } else {
        NetavarkError::msg(format!("exit code {}, message: {}", code, err.error))
    }
}

/// Handle plugin killed result by formatting error message.
pub(crate) fn handle_plugin_killed(plugin_name: Option<&OsStr>) -> NetavarkError {
    if let Some(name) = plugin_name {
        NetavarkError::msg(format!("plugin {:?} killed by signal", name))
    } else {
        NetavarkError::msg("plugin killed by signal")
    }
}

/// Common plugin execution logic that handles spawning the plugin, writing input,
/// reading output, and checking exit status.
pub(crate) fn exec_plugin_common<T: serde::Serialize>(
    plugin_path: &Path,
    args: &[&str],
    input: &T,
) -> NetavarkResult<PluginResult> {
    let mut child = Command::new(plugin_path)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()?;

    let stdin = child.stdin.take().unwrap();
    serde_json::to_writer(&stdin, input)?;
    // Close stdin here to avoid that the plugin waits forever for an EOF.
    // And then we would wait for the child to exit which would cause a hang.
    drop(stdin);

    // Note: We need to buffer the output and then deserialize into the correct type after
    // the plugin exits, since the plugin can return two different json types depending on
    // the exit code.
    let mut buffer: Vec<u8> = Vec::new();

    let mut stdout = child.stdout.take().unwrap();
    // Do not handle error here, we have to wait for the child first.
    let result = stdout.read_to_end(&mut buffer);

    let exit_status = wrap!(child.wait(), "wait for plugin to exit")?;
    if let Some(rc) = exit_status.code() {
        // make sure the buffer is correct
        wrap!(result, "read into buffer")?;
        if rc == 0 {
            Ok(PluginResult::Success(buffer))
        } else {
            Ok(PluginResult::Error { code: rc, buffer })
        }
    } else {
        // If we could not get the exit code then the process was killed by a signal.
        // I don't think it is necessary to read and return the signal so we just return a generic error.
        Ok(PluginResult::Killed)
    }
}

pub struct PluginDriver<'a> {
    path: PathBuf,
    info: DriverInfo<'a>,
}

impl<'a> PluginDriver<'a> {
    pub fn new(path: PathBuf, info: DriverInfo<'a>) -> Self {
        PluginDriver { path, info }
    }
}

impl NetworkDriver for PluginDriver<'_> {
    fn validate(&mut self) -> NetavarkResult<()> {
        // Note the the plugin API does not implement validate().
        // This would just add an extra fork()/exec() overhead which seems
        // undesirable since most times it will work without errors.
        Ok(())
    }

    fn setup(
        &self,
        _netlink_sockets: (&mut Socket<NetlinkRoute>, &mut Socket<NetlinkRoute>),
    ) -> NetavarkResult<(types::StatusBlock, Option<AardvarkEntry<'_>>)> {
        let result = self.exec_plugin(true, self.info.netns_path).wrap(format!(
            "plugin {:?} failed",
            &self.path.file_name().unwrap_or_default()
        ))?;
        // The unwrap should be safe, only if the exec_plugin has a bug this
        // could fail, in which case the test should catch it.
        Ok((result.unwrap(), None))
    }

    fn teardown(
        &self,
        _netlink_sockets: (&mut Socket<NetlinkRoute>, &mut Socket<NetlinkRoute>),
    ) -> NetavarkResult<()> {
        self.exec_plugin(false, self.info.netns_path).wrap(format!(
            "plugin {:?} failed",
            &self.path.file_name().unwrap_or_default()
        ))?;
        Ok(())
    }

    fn network_name(&self) -> String {
        self.info.network.name.clone()
    }
}

impl PluginDriver<'_> {
    fn exec_plugin(&self, setup: bool, netns: &str) -> NetavarkResult<Option<types::StatusBlock>> {
        // problem we always need to clone since you can only deserialize owned data,
        // it is not a problem here but for the plugin it is required.
        // If performance becomes a concern we could use two types for it but the
        // maintenance overhead does not seem worth right now.
        let input = types::NetworkPluginExec {
            container_name: self.info.container_name.clone(),
            container_id: self.info.container_id.clone(),
            port_mappings: self.info.port_mappings.clone(),
            network: self.info.network.clone(),
            network_options: self.info.per_network_opts.clone(),
        };

        let args = vec![if setup { "setup" } else { "teardown" }, netns];
        let result = exec_plugin_common(&self.path, &args, &input)?;

        match result {
            PluginResult::Success(buffer) => {
                if setup {
                    let status = serde_json::from_slice(&buffer)?;
                    Ok(Some(status))
                } else {
                    Ok(None)
                }
            }
            PluginResult::Error { code, buffer } => Err(handle_plugin_error(code, &buffer, None)),
            PluginResult::Killed => Err(handle_plugin_killed(None)),
        }
    }
}
