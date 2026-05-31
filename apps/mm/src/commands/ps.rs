//! `mm ps` — list machines, or print one machine's IP.
use anyhow::Result;

#[derive(Debug, clap::Args)]
pub struct PsArgs {
    /// Print only the IP address of the named machine (for scripting `mm ssh`).
    #[arg(long, value_name = "NAME")]
    pub ip_only: Option<String>,
}

pub fn run(args: PsArgs) -> Result<()> {
    let store = crate::commands::open_store()?;

    if let Some(name) = args.ip_only {
        let record = store
            .get(&name)?
            .ok_or_else(|| anyhow::anyhow!("no such machine: {name}"))?;
        match record.ip {
            Some(ip) => {
                println!("{ip}");
                return Ok(());
            }
            None => anyhow::bail!("machine {name} has no IP yet"),
        }
    }

    let mut machines = store.list()?;
    machines.sort_by(|a, b| a.meta.name.cmp(&b.meta.name));
    println!("{:<24} {:<10} {:<16} IMAGE", "NAME", "STATE", "IP");
    for m in machines {
        let ip =
            m.ip.map(|i| i.to_string())
                .unwrap_or_else(|| "-".to_string());
        println!("{:<24} {:<10} {:<16} {}", m.meta.name, m.state, ip, m.image);
    }
    Ok(())
}
