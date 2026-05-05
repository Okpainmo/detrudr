use log::{error, info};
use std::process::{Command, Output};

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
        if self.dry_run {
            return self.run(&["-D", &self.chain, "-s", ip_address, "-j", "DROP"]);
        }

        match self.rule_exists(ip_address) {
            Ok(true) => {}
            Ok(false) => {
                info!("No iptables rule found for {ip_address}, treating unblock as no-op");
                return true;
            }
            Err(()) => return false,
        }

        self.run(&["-D", &self.chain, "-s", ip_address, "-j", "DROP"])
    }

    fn rule_exists(&self, ip_address: &str) -> Result<bool, ()> {
        match self.output(&["-C", &self.chain, "-s", ip_address, "-j", "DROP"]) {
            Ok(output) => Ok(output.status.success()),
            Err(error) => {
                error!("failed to execute iptables: {error}");
                Err(())
            }
        }
    }

    fn run(&self, args: &[&str]) -> bool {
        if self.dry_run {
            info!("Dry-run iptables command: iptables {}", args.join(" "));
            return true;
        }

        match self.output(args) {
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

    fn output(&self, args: &[&str]) -> std::io::Result<Output> {
        Command::new("iptables").args(args).output()
    }
}
