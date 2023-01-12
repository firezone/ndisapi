use clap::Parser;
use etherparse::{InternetSlice::*, LinkSlice::*, TransportSlice::*, *};
use windows::{
    core::Result,
    Win32::Foundation::HANDLE,
    Win32::System::Threading::{CreateEventW, WaitForSingleObject},
};

#[derive(Parser)]
struct Cli {
    interface_index: usize,
    packets_number: usize,
}

fn main() -> Result<()> {
    let Cli {
        mut interface_index,
        mut packets_number,
    } = Cli::parse();

    interface_index -= 1;

    let driver = ndisapi::Ndisapi::new(ndisapi::NDISRD_DRIVER_NAME)
        .expect("WinpkFilter driver is not installed or failed to load!");

    let (major_version, minor_version, revision) = driver.get_version()?;

    println!(
        "Detected Windows Packet Filter version {}.{}.{}",
        major_version, minor_version, revision
    );

    let adapters = driver.get_tcpip_bound_adapters_info()?;

    if interface_index + 1 > adapters.len() {
        panic!("Interface index is beoynd the number of available interfaces");
    }

    println!(
        "Using interface {} with {} packets",
        adapters[interface_index].get_name(),
        packets_number
    );

    // Create Win32 event
    let event: HANDLE;
    unsafe {
        event = CreateEventW(None, true, false, None)?;
    }

    // Set the event within the driver
    driver.set_packet_event(adapters[interface_index].get_handle(), event)?;

    // Put network interface into the tunnel mode
    driver.set_adapter_mode(
        adapters[interface_index].get_handle(),
        ndisapi::FilterFlags::MSTCP_FLAG_SENT_RECEIVE_TUNNEL,
    )?;

    // Allocate single IntermediateBuffer on the stack
    let mut ib = ndisapi::IntermediateBuffer::default();

    // Initialize EthPacket to pass to driver API
    let mut packet = ndisapi::EthRequest {
        adapter_handle: adapters[interface_index].get_handle(),
        packet: ndisapi::EthPacket {
            buffer: &mut ib as *mut ndisapi::IntermediateBuffer,
        },
    };

    while packets_number > 0 {
        unsafe {
            WaitForSingleObject(event, u32::MAX);
        }
        while unsafe { driver.read_packet(&mut packet) }.ok().is_some() {
            // Print packet information
            if ib.get_device_flags() == ndisapi::DirectionFlags::PACKET_FLAG_ON_SEND {
                println!("\n{} - MSTCP --> Interface\n", packets_number);
            } else {
                println!("\n{} - Interface --> MSTCP\n", packets_number);
            }

            // Decrement packets counter
            packets_number -= 1;

            // Print some informations about the sliced packet
            match SlicedPacket::from_ethernet(&ib.buffer.0) {
                Err(value) => println!("Err {:?}", value),
                Ok(value) => {
                    if let Some(Ethernet2(value)) = value.link {
                        println!(" Ethernet {:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X} => {:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
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
                            value.destination()[5])
                    }

                    match value.ip {
                        Some(Ipv4(value, extensions)) => {
                            println!(
                                "  Ipv4 {:?} => {:?}",
                                value.source_addr(),
                                value.destination_addr()
                            );
                            if !extensions.is_empty() {
                                println!("    {:?}", extensions);
                            }
                        }
                        Some(Ipv6(value, extensions)) => {
                            println!(
                                "  Ipv6 {:?} => {:?}",
                                value.source_addr(),
                                value.destination_addr()
                            );
                            if !extensions.is_empty() {
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
            if ib.get_device_flags() == ndisapi::DirectionFlags::PACKET_FLAG_ON_SEND {
                match unsafe { driver.send_packet_to_adapter(&packet) } {
                    Ok(_) => {}
                    Err(err) => println!("Error sending packet to adapter. Error code = {err}"),
                };
            } else {
                match unsafe { driver.send_packet_to_mstcp(&packet) } {
                    Ok(_) => {}
                    Err(err) => println!("Error sending packet to mstcp. Error code = {err}"),
                }
            }

            if packets_number == 0 {
                println!("Filtering complete\n");
                break;
            }
        }
    }

    Ok(())
}
