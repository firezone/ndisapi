use ndisapi::driver::driver::NDISRD_DRIVER_NAME;
use ndisapi::ndisapi::*;
use windows::core::Result;

fn main() -> Result<()> {
    let result = Ndisapi::new(NDISRD_DRIVER_NAME);

    let driver = match result {
        Ok(ndisapi) => ndisapi,
        Err(err) => panic!(
            "WinpkFilter driver is not installed or failed to load! Error code: {}",
            err.to_string()
        ),
    };

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
