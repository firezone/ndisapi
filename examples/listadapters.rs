use windows::core::Result;

fn main() -> Result<()> {
    let driver = ndisapi::Ndisapi::new(ndisapi::NDISRD_DRIVER_NAME)
        .expect("WinpkFilter driver is not installed or failed to load!");

    let (major_version, minor_version, revision) = driver.get_version()?;

    println!(
        "Detected Windows Packet Filter version {}.{}.{}",
        major_version, minor_version, revision
    );
    let adapters = driver.get_tcpip_bound_adapters_info()?;

    for (index, value) in adapters.iter().enumerate() {
        println!("{}. {}", index + 1, value.get_name());
        println!("\t Medium: {}", value.get_medium());
        println!("\t MAC: {:?}", value.get_hw_address());
        println!("\t MTU: {}", value.get_mtu());
        println!(
            "\t FilterFlags: {:?}",
            driver.get_adapter_mode(value.get_handle()).unwrap()
        );

        match driver.get_hw_packet_filter(value.get_handle()) {
            Err(err) => println!(
                "Getting OID_GEN_CURRENT_PACKET_FILTER Error: {}",
                err.message().to_string_lossy()
            ),
            Ok(current_packet_filter) => println!(
                "\t OID_GEN_CURRENT_PACKET_FILTER: 0x{:08X}",
                current_packet_filter
            ),
        }
    }

    Ok(())
}
