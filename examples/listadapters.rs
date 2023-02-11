use ndisapi::Ndisapi;
use windows::core::Result;

const OID_802_3_CURRENT_ADDRESS: u32 = 0x01010102;

fn main() -> Result<()> {
    let driver = ndisapi::Ndisapi::new(ndisapi::NDISRD_DRIVER_NAME)
        .expect("WinpkFilter driver is not installed or failed to load!");

    println!(
        "Detected Windows Packet Filter version {}",
        driver.get_version()?
    );

    let adapters = driver.get_tcpip_bound_adapters_info()?;

    for (index, value) in adapters.iter().enumerate() {
        // Display the information about each network interface provided by the get_tcpip_bound_adapters_info
        let network_interface_name = match Ndisapi::get_friendly_adapter_name(value.get_name()) {
            Ok(interface_name) => interface_name,
            Err(err) => format!(r#"UNKNOWN NETWORK INTERFACE Error code: {err}"#),
        };
        println!(
            "{}. {}\n\t{}",
            index + 1,
            network_interface_name,
            value.get_name(),
        );
        println!("\t Medium: {}", value.get_medium());
        println!(
            "\t MAC: {:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
            value.get_hw_address()[0],
            value.get_hw_address()[1],
            value.get_hw_address()[2],
            value.get_hw_address()[3],
            value.get_hw_address()[4],
            value.get_hw_address()[5]
        );
        println!("\t MTU: {}", value.get_mtu());
        println!(
            "\t FilterFlags: {:?}",
            driver.get_adapter_mode(value.get_handle()).unwrap()
        );

        // Query hardware packet filter for the adapter using built wrapper for ndis_get_request
        match driver.get_hw_packet_filter(value.get_handle()) {
            Err(err) => println!(
                "Getting OID_GEN_CURRENT_PACKET_FILTER Error: {}",
                err.message().to_string_lossy()
            ),
            Ok(current_packet_filter) => {
                println!("\t OID_GEN_CURRENT_PACKET_FILTER: 0x{current_packet_filter:08X}")
            }
        }

        // Query MAC address of the network adapter using ndis_get_request directly
        let mut current_address_request = ndisapi::PacketOidData::new(
            value.get_handle(),
            OID_802_3_CURRENT_ADDRESS,
            ndisapi::MacAddress::default(),
        );
        if let Err(err) = driver.ndis_get_request::<_>(&mut current_address_request) {
            println!(
                "Getting OID_802_3_CURRENT_ADDRESS Error: {}",
                err.message().to_string_lossy()
            )
        } else {
            println!(
                "\t OID_802_3_CURRENT_ADDRESS: {}",
                current_address_request.data
            )
        }
    }

    Ok(())
}
