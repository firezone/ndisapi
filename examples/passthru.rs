use windows::{
    core::Result,
    Win32::Foundation::HANDLE,
    Win32::System::Threading::{CreateEventW, WaitForSingleObject},
};

use std::env;

use ndisapi;

use etherparse::{InternetSlice::*, LinkSlice::*, TransportSlice::*, *};

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();

    let interface_idx: usize = args[1]
        .parse::<usize>()
        .expect("Failed to parse network interface index")
        - 1;
    let mut packets_num: usize = args[2]
        .parse::<usize>()
        .expect("Failed to parse number of packet to filter");

    let result = ndisapi::Ndisapi::new(ndisapi::NDISRD_DRIVER_NAME);

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

    if interface_idx + 1 > adapters.len() {
        panic!("Interface index is beoynd the number of available interfaces");
    }

    println!(
        "Using interface {} with {} packets",
        adapters[interface_idx].name, packets_num
    );

    // Create Win32 event
    let event: HANDLE;
    unsafe {
        event = CreateEventW(None, true, false, None)?;
    }

    // Set the event within the driver
    driver.set_packet_event(adapters[interface_idx].handle, event)?;

    // Put network interface into the tunnel mode
    driver.set_adapter_mode(
        adapters[interface_idx].handle,
        ndisapi::MSTCP_FLAG_SENT_TUNNEL | ndisapi::MSTCP_FLAG_RECV_TUNNEL,
    )?;

    // Allocate single IntermediateBuffer on the stack
    let mut ib = ndisapi::IntermediateBuffer::default();

    // Initialize EthPacket to pass to driver API
    let mut eth_packet = ndisapi::EthPacket {
        buffer: &mut ib as *mut ndisapi::IntermediateBuffer,
    };

    while packets_num > 0 {
        unsafe {
            WaitForSingleObject(event, u32::MAX);
        }
        while driver.read_packet(adapters[interface_idx].handle, &mut eth_packet) {
            // Decrement packets counter
            packets_num -= 1;

            // Print packet information
            if ib.device_flags == ndisapi::PACKET_FLAG_ON_SEND {
                println!("\n{} - MSTCP --> Interface\n", packets_num);
            } else {
                println!("\n{} - Interface --> MSTCP\n", packets_num);
            }

            // Print some informations about the sliced packet
            match SlicedPacket::from_ethernet(&ib.buffer.0) {
                Err(value) => println!("Err {:?}", value),
                Ok(value) => {
                    match value.link {
                    Some(Ethernet2(value)) => println!("  Ethernet {:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X} => {:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}", 
                    value.source()[0],
                    value.source()[1],
                    value.source()[2],
                    value.source()[3],
                    value.source()[4],
                    value.source()[5],
                    value.destination()[0],
                    value.destination()[1],
                    value.destination()[2],
                    value.destination()[3],
                    value.destination()[4],
                    value.destination()[5]),
                    None => {}
                }

                    match value.ip {
                        Some(Ipv4(value, extensions)) => {
                            println!(
                                "  Ipv4 {:?} => {:?}",
                                value.source_addr(),
                                value.destination_addr()
                            );
                            if false == extensions.is_empty() {
                                println!("    {:?}", extensions);
                            }
                        }
                        Some(Ipv6(value, extensions)) => {
                            println!(
                                "  Ipv6 {:?} => {:?}",
                                value.source_addr(),
                                value.destination_addr()
                            );
                            if false == extensions.is_empty() {
                                println!("    {:?}", extensions);
                            }
                        }
                        None => {}
                    }

                    match value.transport {
                        Some(Icmpv4(value)) => println!(" Icmpv4 {:?}", value),
                        Some(Icmpv6(value)) => println!(" Icmpv6 {:?}", value),
                        Some(Udp(value)) => println!(
                            "  UDP {:?} -> {:?}",
                            value.source_port(),
                            value.destination_port()
                        ),
                        Some(Tcp(value)) => {
                            println!(
                                "  TCP {:?} -> {:?}",
                                value.source_port(),
                                value.destination_port()
                            );
                        }
                        Some(Unknown(ip_protocol)) => {
                            println!("  Unknwon Protocol (ip protocol number {:?}", ip_protocol)
                        }
                        None => {}
                    }
                }
            }

            // Re-inject the packet back into the network stack
            if ib.device_flags == ndisapi::PACKET_FLAG_ON_SEND {
                driver.send_packet_to_adapter(adapters[interface_idx].handle, &mut eth_packet);
            } else {
                driver.send_packet_to_mstcp(adapters[interface_idx].handle, &mut eth_packet);
            }

            if packets_num == 0 {
                println!("Filtering complete\n");
                break;
            }
        }
    }

    Ok(())
}
