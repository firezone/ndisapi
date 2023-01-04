use windows::{
    core::Result,
    Win32::Foundation::HANDLE,
    Win32::System::Threading::{CreateEventW, WaitForSingleObject},
};

use std::{collections::VecDeque, env};

use ndisapi::ndisapi::*;

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

    if interface_idx + 1 > adapters.len() {
        panic!("Interface index is beoynd the number of available interfaces");
    }

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
        ndisapi::driver::driver::MSTCP_FLAG_SENT_TUNNEL
            | ndisapi::driver::driver::MSTCP_FLAG_RECV_TUNNEL,
    )?;

    let mut ib: VecDeque<Box<ndisapi::driver::driver::IntermediateBuffer>> = VecDeque::new();
    let mut to_mstcp: VecDeque<Box<ndisapi::driver::driver::IntermediateBuffer>> = VecDeque::new();
    let mut to_adapter: VecDeque<Box<ndisapi::driver::driver::IntermediateBuffer>> =
        VecDeque::new();
    for _i in 0..256 {
        ib.push_back(Box::new(
            ndisapi::driver::driver::IntermediateBuffer::default(),
        ));
    }

    let mut packets_read: usize;
    while packets_num > 0 {
        unsafe {
            WaitForSingleObject(event, u32::MAX);
        }
        while {
            packets_read =
                driver.read_packets::<_, 256>(adapters[interface_idx].handle, ib.iter_mut());
            packets_read > 0
        } {
            // Decrement packets counter
            packets_num = packets_num.saturating_sub(packets_read);

            for _ in 0..packets_read {
                let packet = ib.pop_front().unwrap();
                // Print packet information
                if packet.device_flags == ndisapi::driver::driver::PACKET_FLAG_ON_SEND {
                    println!("\n{} - MSTCP --> Interface\n", packets_num);
                } else {
                    println!("\n{} - Interface --> MSTCP\n", packets_num);
                }

                // Print some informations about the sliced packet
                match SlicedPacket::from_ethernet(&packet.buffer.0) {
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
                                // let options: Vec<Result<TcpOptionElement, TcpOptionReadError>> = value.options_iterator().collect();
                                // println!("    {:?}", options);
                            }
                            Some(Unknown(ip_protocol)) => {
                                println!("  Unknwon Protocol (ip protocol number {:?}", ip_protocol)
                            }
                            None => {}
                        }
                    }
                }

                if packet.device_flags == ndisapi::driver::driver::PACKET_FLAG_ON_SEND {
                    to_adapter.push_back(packet);
                } else {
                    to_mstcp.push_back(packet);
                }
            }

            // Re-inject packets back into the network stack
            if to_adapter.is_empty() == false {
                driver.send_packets_to_adapter::<_, 256>(
                    adapters[interface_idx].handle,
                    to_adapter.iter_mut(),
                );
                ib.append(&mut to_adapter);
            }

            if to_mstcp.is_empty() == false {
                driver.send_packets_to_mstcp::<_, 256>(
                    adapters[interface_idx].handle,
                    to_mstcp.iter_mut(),
                );
                ib.append(&mut to_mstcp);
            }

            if packets_num == 0 {
                println!("Filtering complete\n");
                break;
            }
        }
    }

    Ok(())
}
