use log::{error, info};
use std::process::Command;

#[derive(Clone, Debug)]
pub struct IptablesBlocker {
    chain: String,
    dry_run: bool,
}

impl IptablesBlocker {
    pub fn new(chain: String, dry_run: bool) -> Self {
        Self { chain, dry_run }
    }

    pub fn block(&self, ip_address: &str) -> bool {
        self.run(&["-I", &self.chain, "-s", ip_address, "-j", "DROP"])
    }

    pub fn unblock(&self, ip_address: &str) -> bool {
        self.run(&["-D", &self.chain, "-s", ip_address, "-j", "DROP"])
    }

    fn run(&self, args: &[&str]) -> bool {
        if self.dry_run {
            info!("Dry-run iptables command: iptables {}", args.join(" "));
            return true;
        }

        match Command::new("iptables").args(args).output() {
            Ok(output) if output.status.success() => true,
            Ok(output) => {
                error!(
                    "iptables command failed: {}",
                    String::from_utf8_lossy(&output.stderr).trim()
                );
                false
            }
            Err(error) => {
                error!("failed to execute iptables: {error}");
                false
            }
        }
    }
}
