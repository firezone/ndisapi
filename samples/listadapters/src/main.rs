pub(crate) use windows::core::*;

use ndisapi::ndisapi::*;

fn main() -> Result<()> {
    let driver = Ndisapi::default();

    if !driver.is_driver_loaded() {
        panic!("WinpkFilter driver is not installed or failed to load!");
    }

    let (major_version, minor_version, revision) = driver.get_version()?;

    println!(
        "Detected Windows Packet Filter version {}.{}.{}",
        major_version, minor_version, revision
    );
    let adapters = driver.get_tcpip_bound_adapters_info()?;

    for (index, value) in adapters.iter().enumerate() {
        println!("{}. {}", index + 1, value.name);
        println!("\t Medium: {}", value.medium);
        println!("\t MAC: {:?}", value.hw_address);
        println!("\t MTU: {}", value.mtu);
    }

    Ok(())
}
