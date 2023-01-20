use windows::core::Result;

const OID_802_3_CURRENT_ADDRESS: u32 = 0x01010102;

#[derive(Default)]
struct MacAddress([u8; ndisapi::ETHER_ADDR_LENGTH]);

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
            Ok(current_packet_filter) => println!(
                "\t OID_GEN_CURRENT_PACKET_FILTER: 0x{:08X}",
                current_packet_filter
            ),
        }

        // Query MAC address of the network adapter using ndis_get_request directly
        let mut current_address_request = ndisapi::PacketOidData::new(
            value.get_handle(),
            OID_802_3_CURRENT_ADDRESS,
            MacAddress::default(),
        );
        if let Err(err) = driver.ndis_get_request::<_>(&mut current_address_request) {
            println!(
                "Getting OID_802_3_CURRENT_ADDRESS Error: {}",
                err.message().to_string_lossy()
            )
        } else {
            println!(
                "\t OID_802_3_CURRENT_ADDRESS: {:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
                current_address_request.data.0[0],
                current_address_request.data.0[1],
                current_address_request.data.0[2],
                current_address_request.data.0[3],
                current_address_request.data.0[4],
                current_address_request.data.0[5],
            )
        }
    }

    Ok(())
}
