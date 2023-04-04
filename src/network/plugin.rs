use std::{
    io::Read,
    path::PathBuf,
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
        _netlink_sockets: (&mut super::netlink::Socket, &mut super::netlink::Socket),
    ) -> NetavarkResult<(types::StatusBlock, Option<AardvarkEntry>)> {
        let result = self.exec_plugin(true, self.info.netns_path).wrap(format!(
            "plugin \"{}\" failed",
            &self
                .path
                .file_name()
                .unwrap_or_default()
                .to_str()
                .unwrap_or_default()
        ))?;
        // The unwrap should be safe, only if the exec_plugin has a bug this
        // could fail, in which case the test should catch it.
        Ok((result.unwrap(), None))
    }

    fn teardown(
        &self,
        _netlink_sockets: (&mut super::netlink::Socket, &mut super::netlink::Socket),
    ) -> NetavarkResult<()> {
        self.exec_plugin(false, self.info.netns_path).wrap(format!(
            "plugin \"{}\" failed",
            &self
                .path
                .file_name()
                .unwrap_or_default()
                .to_str()
                .unwrap_or_default()
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

        let mut child = Command::new(&self.path)
            .arg(if setup { "setup" } else { "teardown" })
            .arg(netns)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()?;

        let stdin = child.stdin.take().unwrap();
        serde_json::to_writer(&stdin, &input)?;
        // Close stdin here to avoid that the plugin waits forever for an EOF.
        // And then we would wait for the child to exit which would cause a hang.
        drop(stdin);

        // Note: We need to buffer the output and then deserialize into the correct type after
        // the plugin exits, Since the plugin can return two different json types depending on
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
                // read status block and setup
                if setup {
                    let status = serde_json::from_slice(&buffer)?;
                    return Ok(Some(status));
                } else {
                    return Ok(None);
                }
            } else {
                // exit code not 0 => error
                let err: JsonError = serde_json::from_slice(&buffer)?;
                return Err(NetavarkError::msg(format!(
                    "exit code {}, message: {}",
                    rc, err.error
                )));
            }
        }
        // If we could not get the exit code then the process was killed by a signal.
        // I don't think it is necessary to read and return the signal so we just return a generic error.
        Err(NetavarkError::msg("plugin killed by signal"))
    }
}
