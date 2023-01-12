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

const PACKET_NUMBER: usize = 256;

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
    let event: HANDLE = unsafe { CreateEventW(None, true, false, None)? };

    // Set the event within the driver
    driver.set_packet_event(adapters[interface_index].get_handle(), event)?;

    // Put network interface into the tunnel mode
    driver.set_adapter_mode(
        adapters[interface_index].get_handle(),
        ndisapi::FilterFlags::MSTCP_FLAG_SENT_RECEIVE_TUNNEL,
    )?;

    // Container to store IntermediateBuffers allocated on the heap
    let mut ibs: Vec<ndisapi::IntermediateBuffer> = vec![Default::default(); PACKET_NUMBER];

    // Containers to read/write IntermediateBuffers from/to the driver
    let mut to_read = ndisapi::EthMRequest::new(adapters[interface_index].get_handle());
    let mut to_mstcp: ndisapi::EthMRequest<PACKET_NUMBER> =
        ndisapi::EthMRequest::new(adapters[interface_index].get_handle());
    let mut to_adapter: ndisapi::EthMRequest<PACKET_NUMBER> =
        ndisapi::EthMRequest::new(adapters[interface_index].get_handle());

    // Initialize the read EthMRequest object
    for ib in &mut ibs {
        to_read.packets[to_read.packet_number as usize] = ndisapi::EthPacket {
            buffer: ib as *mut _,
        };
        to_read.packet_number += 1;
    }

    while packets_number > 0 {
        unsafe {
            WaitForSingleObject(event, u32::MAX);
        }

        let mut packets_read: usize;

        while {
            packets_read =
                unsafe { driver.read_packets::<PACKET_NUMBER>(&mut to_read) }.unwrap_or(0usize);
            packets_read > 0
        } {
            // Decrement packets counter
            packets_number = packets_number.saturating_sub(packets_read);

            for i in 0..packets_read {
                let packet = unsafe { to_read.packets[i].get_buffer() };
                // Print packet information
                if packet.get_device_flags() == ndisapi::DirectionFlags::PACKET_FLAG_ON_SEND {
                    println!(
                        "\n{} - MSTCP --> Interface\n",
                        packets_number + (packets_read - i)
                    );
                } else {
                    println!(
                        "\n{} - Interface --> MSTCP\n",
                        packets_number + (packets_read - i)
                    );
                }

                // Print some informations about the sliced packet

                match SlicedPacket::from_ethernet(&packet.buffer.0) {
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

                if packet.get_device_flags() == ndisapi::DirectionFlags::PACKET_FLAG_ON_SEND {
                    to_adapter.packets[to_adapter.packet_number as usize] = to_read.packets[i];
                    to_adapter.packet_number += 1;
                } else {
                    to_mstcp.packets[to_mstcp.packet_number as usize] = to_read.packets[i];
                    to_mstcp.packet_number += 1;
                }
            }

            // Re-inject packets back into the network stack
            if to_adapter.packet_number > 0 {
                match unsafe { driver.send_packets_to_adapter::<PACKET_NUMBER>(&to_adapter) } {
                    Ok(_) => {}
                    Err(err) => println!("Error sending packet to adapter. Error code = {err}"),
                }
                to_adapter.packet_number = 0;
            }

            if !to_mstcp.packet_number > 0 {
                match unsafe { driver.send_packets_to_mstcp::<PACKET_NUMBER>(&to_mstcp) } {
                    Ok(_) => {}
                    Err(err) => println!("Error sending packet to mstcp. Error code = {err}"),
                };
                to_mstcp.packet_number = 0;
            }

            if packets_number == 0 {
                println!("Filtering complete\n");
                break;
            }
        }
    }

    Ok(())
}
