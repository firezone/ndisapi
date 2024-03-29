/// This example demonstrates the fundamental usage of active filtering modes in packet processing. By selecting a
/// network interface and configuring it to operate in a filtering mode, both sent and received packets are queued.
/// The example registers a Win32 event through the `Ndisapi::set_packet_event` function and enters a waiting state
/// for incoming packets. As packets are received, their content is decoded and printed on the console screen, offering
/// a real-time visualization of network traffic. This example resembles the `passthru` utility but employs bulk
/// packet sending and receiving to optimize performance.
use clap::Parser;
use etherparse::{InternetSlice::*, LinkSlice::*, TransportSlice::*, *};
use windows::{
    core::Result,
    Win32::Foundation::HANDLE,
    Win32::System::Threading::{CreateEventW, WaitForSingleObject},
};

#[derive(Parser)]
struct Cli {
    /// Network interface index (please use listadapters example to determine the right one)
    #[clap(short, long)]
    interface_index: usize,
    /// Number of packets to read from the specified network interface
    #[clap(short, long)]
    packets_number: usize,
}

const PACKET_NUMBER: usize = 256;

fn main() -> Result<()> {
    // Parse command line arguments.
    let Cli {
        mut interface_index,
        mut packets_number,
    } = Cli::parse();

    // Decrement the interface index since it's zero-based.
    interface_index -= 1;

    // Initialize the NDISAPI driver.
    let driver = ndisapi::Ndisapi::new("NDISRD")
        .expect("WinpkFilter driver is not installed or failed to load!");

    // Print the detected Windows Packet Filter version.
    println!(
        "Detected Windows Packet Filter version {}",
        driver.get_version()?
    );

    // Get a list of TCP/IP bound adapters.
    let adapters = driver.get_tcpip_bound_adapters_info()?;

    // Validate the user-specified interface index.
    if interface_index + 1 > adapters.len() {
        panic!("Interface index is beyond the number of available interfaces");
    }

    // Print the selected interface and number of packets to process.
    println!(
        "Using interface {} with {} packets",
        adapters[interface_index].get_name(),
        packets_number
    );

    // Create a Win32 event.
    let event: HANDLE = unsafe { CreateEventW(None, true, false, None)? };

    // Set the event within the driver.
    driver.set_packet_event(adapters[interface_index].get_handle(), event)?;

    // Put the network interface into tunnel mode.
    driver.set_adapter_mode(
        adapters[interface_index].get_handle(),
        ndisapi::FilterFlags::MSTCP_FLAG_SENT_RECEIVE_TUNNEL,
    )?;

    // Initialize a container to store IntermediateBuffers allocated on the heap.
    let mut ibs: Vec<ndisapi::IntermediateBuffer> = vec![Default::default(); PACKET_NUMBER];

    // Initialize containers to read/write IntermediateBuffers from/to the driver.
    let mut to_read = ndisapi::EthMRequest::new(adapters[interface_index].get_handle());
    let mut to_mstcp: ndisapi::EthMRequest<PACKET_NUMBER> =
        ndisapi::EthMRequest::new(adapters[interface_index].get_handle());
    let mut to_adapter: ndisapi::EthMRequest<PACKET_NUMBER> =
        ndisapi::EthMRequest::new(adapters[interface_index].get_handle());

    // Initialize the read EthMRequest object.
    for ib in &mut ibs {
        to_read.push(ndisapi::EthPacket {
            buffer: ib as *mut _,
        })?;
    }

    // Main loop: Process packets until the specified number of packets is reached.
    while packets_number > 0 {
        // Wait for the event to be signaled.
        unsafe {
            WaitForSingleObject(event, u32::MAX);
        }

        // Read packets from the driver.
        let mut packets_read: usize;
        while {
            packets_read =
                unsafe { driver.read_packets::<PACKET_NUMBER>(&mut to_read) }.unwrap_or(0usize);
            packets_read > 0
        } {
            // Decrement the packets counter.
            packets_number = packets_number.saturating_sub(packets_read);

            // Process each packet.
            for i in 0..packets_read {
                let mut eth = to_read.at(i).unwrap();
                let packet = unsafe { eth.get_buffer_mut() };

                // Print packet direction and remaining packets.
                if packet.get_device_flags() == ndisapi::DirectionFlags::PACKET_FLAG_ON_SEND {
                    println!(
                        "\nMSTCP --> Interface ({} bytes) remaining packets {}\n",
                        packet.get_length(),
                        packets_number + (packets_read - i)
                    );
                } else {
                    println!(
                        "\nInterface --> MSTCP ({} bytes) remaining packets {}\n",
                        packet.get_length(),
                        packets_number + (packets_read - i)
                    );
                }

                // Print packet information
                print_packet_info(packet);

                if packet.get_device_flags() == ndisapi::DirectionFlags::PACKET_FLAG_ON_SEND {
                    to_adapter.push(eth)?;
                } else {
                    to_mstcp.push(eth)?;
                }
            }

            // Re-inject packets back into the network stack
            if to_adapter.get_packet_number() > 0 {
                match unsafe { driver.send_packets_to_adapter::<PACKET_NUMBER>(&to_adapter) } {
                    Ok(_) => {}
                    Err(err) => println!("Error sending packet to adapter. Error code = {err}"),
                }
                to_adapter.reset();
            }

            if !to_mstcp.get_packet_number() > 0 {
                match unsafe { driver.send_packets_to_mstcp::<PACKET_NUMBER>(&to_mstcp) } {
                    Ok(_) => {}
                    Err(err) => println!("Error sending packet to mstcp. Error code = {err}"),
                };
                to_mstcp.reset();
            }

            if packets_number == 0 {
                println!("Filtering complete\n");
                break;
            }
        }
    }

    Ok(())
}

/// Print detailed information about a network packet.
///
/// This function takes an `IntermediateBuffer` containing a network packet and prints various
/// details about the packet, such as Ethernet, IPv4, IPv6, ICMPv4, ICMPv6, UDP, and TCP information.
///
/// # Arguments
///
/// * `packet` - A mutable reference to an `ndisapi::IntermediateBuffer` containing the network packet.
///
/// # Examples
///
/// ```no_run
/// let mut packet: ndisapi::IntermediateBuffer = ...;
/// print_packet_info(&mut packet);
/// ```
fn print_packet_info(packet: &mut ndisapi::IntermediateBuffer) {
    // Attempt to create a SlicedPacket from the Ethernet frame.
    match SlicedPacket::from_ethernet(&packet.buffer.0) {
        // If there's an error, print it.
        Err(value) => println!("Err {value:?}"),

        // If successful, proceed with printing packet information.
        Ok(value) => {
            // Print Ethernet information if available.
            if let Some(Ethernet2(value)) = value.link {
                println!(
                    " Ethernet {} => {}",
                    ndisapi::MacAddress::from_slice(&value.source()[..]).unwrap(),
                    ndisapi::MacAddress::from_slice(&value.destination()[..]).unwrap(),
                );
            }

            // Print IP information if available.
            match value.ip {
                Some(Ipv4(value, extensions)) => {
                    println!(
                        "  Ipv4 {:?} => {:?}",
                        value.source_addr(),
                        value.destination_addr()
                    );
                    if !extensions.is_empty() {
                        println!("    {extensions:?}");
                    }
                }
                Some(Ipv6(value, extensions)) => {
                    println!(
                        "  Ipv6 {:?} => {:?}",
                        value.source_addr(),
                        value.destination_addr()
                    );
                    if !extensions.is_empty() {
                        println!("    {extensions:?}");
                    }
                }
                None => {}
            }

            // Print transport layer information if available.
            match value.transport {
                Some(Icmpv4(value)) => println!(" Icmpv4 {value:?}"),
                Some(Icmpv6(value)) => println!(" Icmpv6 {value:?}"),
                Some(Udp(value)) => println!(
                    "   UDP {:?} -> {:?}",
                    value.source_port(),
                    value.destination_port()
                ),
                Some(Tcp(value)) => {
                    println!(
                        "   TCP {:?} -> {:?}",
                        value.source_port(),
                        value.destination_port()
                    );
                }
                Some(Unknown(ip_protocol)) => {
                    println!("  Unknown Protocol (ip protocol number {ip_protocol:?})")
                }
                None => {}
            }
        }
    }
}
