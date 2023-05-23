use clap::Parser;
use etherparse::{InternetSlice::*, LinkSlice::*, TransportSlice::*, *};
use futures::{task::AtomicWaker, Future};
use ndisapi::{EthRequest, FilterFlags};
use std::{
    ffi::c_void,
    pin::Pin,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    task::{Context, Poll},
};
use tokio::{runtime::Builder, sync::oneshot};
use windows::{
    core::Result,
    Win32::{
        Foundation::{GetLastError, CloseHandle, BOOLEAN, HANDLE},
        System::Threading::{
            CreateEventW, RegisterWaitForSingleObject, ResetEvent, UnregisterWaitEx, INFINITE,
            WT_EXECUTEINWAITTHREAD,
        },
    },
};

// The struct NdisapiAdapter represents a network adapter with its associated driver and relevant handles.
pub struct NdisapiAdapter {
    /// The network driver for the adapter.
    driver: Arc<ndisapi::Ndisapi>, 
    /// The handle of the network adapter.
    adapter_handle: HANDLE,
    /// A future that resolves when a Win32 event is signaled.
    notif: Win32EventFuture,
}

impl NdisapiAdapter {
    /// Create NdisapiAdapter
    pub fn new(
        driver: Arc<ndisapi::Ndisapi>, // The network driver for the adapter.
        adapter_handle: HANDLE,        // The handle of the network adapter.
        flags: ndisapi::FilterFlags,   // The filter flags for the adapter.
    ) -> Result<Self> {
        let event_handle = unsafe {
            // Creating a Win32 event without a name. The event is manual-reset and initially non-signaled.
            CreateEventW(None, true, false, None)?
        };

        // Setting the event for packet capture for the specified adapter.
        driver.set_packet_event(adapter_handle, event_handle)?;

        // Setting the operating mode for the specified adapter.
        driver.set_adapter_mode(adapter_handle, flags)?;

        Ok(Self {
            adapter_handle,
            driver,
            notif: Win32EventFuture::new(event_handle)?, // Creating a new Win32EventFuture with the event handle.
        })
    }

    /// Wait for a packet event to be signaled before continuing with the packet capture process.
    async fn wait_for_packet(&mut self) -> Result<()> {
        Pin::new(&mut self.notif).await
    }

    /// Read a packet from the network adapter and return it as an `EthRequest` struct.
    pub async fn read_packet(&mut self, packet: &mut EthRequest) -> Result<()> {
        let driver = self.driver.clone();

        // first try to read packet
        if unsafe { driver.read_packet(packet) }.is_ok() {
            return Ok(());
        }

        let result = self.wait_for_packet().await; // wait for packet event
        match result {
            Ok(_) => {
                if unsafe { driver.read_packet(packet) }.ok().is_some() {
                    Ok(())
                } else {
                    Err(unsafe { GetLastError() }.into())
                }
            }
            Err(e) => Err(e),
        }
    }
}

// Implementing the Drop trait for the NdisapiAdapter struct.
impl Drop for NdisapiAdapter {
    /// The drop method will be called automatically when the NdisapiAdapter object goes out of scope.
    fn drop(&mut self) {
        // Setting the operating mode for the specified adapter to default.
        _ = self
            .driver
            .set_adapter_mode(self.adapter_handle, FilterFlags::from_bits_truncate(0));

        // Setting the packet event for the specified adapter to NULL.
        _ = self.driver.set_packet_event(self.adapter_handle, HANDLE(0));
    }
}

/// A future that resolves when a Win32 event is signaled.
struct Win32EventFuture {
    #[allow(dead_code)]
    notif: Win32EventNotification, // The Win32 event notification object.
    waker: Arc<AtomicWaker>,       // An atomic waker for waking the future.
    ready: Arc<AtomicBool>,        // An atomic boolean indicating whether the event is ready.
}

impl Win32EventFuture {
    /// Create a new `Win32EventFuture` instance with the specified event handle.
    fn new(event_handle: HANDLE) -> Result<Self> {
        let waker = Arc::new(AtomicWaker::new());
        let ready = Arc::new(AtomicBool::new(false));

        Ok(Self {
            waker: waker.clone(),
            ready: ready.clone(),
            notif: Win32EventNotification::new(
                event_handle,
                Box::new(move |_| {
                    println!("=========================================================================================================================================");
                    ready.store(true, Ordering::SeqCst);
                    waker.wake();
                    unsafe { ResetEvent(event_handle) };
                }),
            )?,
        })
    }

    /// Poll for the packet event.
    pub fn poll_packet_event(&mut self, cx: &mut Context) -> Poll<Result<()>> {
        if self.ready.swap(false, Ordering::Relaxed) {
            Poll::Ready(Ok(()))
        } else {
            self.waker.register(cx.waker());
            Poll::Pending
        }
    }
}

impl Future for Win32EventFuture {
    type Output = Result<()>;

    /// Poll the future to check if the event is ready.
    fn poll(self: std::pin::Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        Pin::into_inner(self).poll_packet_event(cx)
    }
}
/// Win32 event notifications
struct Win32EventNotification {
    win32_event: HANDLE,               // The Win32 event handle.
    wait_object: HANDLE,               // The wait object handle.
    callback: *mut Win32EventCallback, // A pointer to the Win32 event callback function.
}

impl std::fmt::Debug for Win32EventNotification {
    /// Implementing the Debug trait for the Win32EventNotification struct.
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "Win32EventNotification: {:?}", self.wait_object)
    }
}

type Win32EventCallback = Box<dyn Fn(BOOLEAN) + Send>; // A type alias for the Win32 event callback function.

impl Win32EventNotification {
    /// Register for Win32 event notifications.
    fn new(win32_event: HANDLE, cb: Win32EventCallback) -> Result<Self> {
        // Defining the global callback function for the Win32 event.
        unsafe extern "system" fn global_callback(caller_context: *mut c_void, time_out: BOOLEAN) {
            (**(caller_context as *mut Win32EventCallback))(time_out)
        }

        let callback = Box::into_raw(Box::new(cb)); // Creating a raw pointer to the callback function.
        let mut wait_object: HANDLE = HANDLE(0);

        // Registering for Win32 event notifications.
        let rc = unsafe {
            RegisterWaitForSingleObject(
                &mut wait_object,
                win32_event,
                Some(global_callback),
                Some(callback as *const c_void),
                INFINITE,
                WT_EXECUTEINWAITTHREAD,
            )
        };

        // Check if the registration was successful.
        if rc.as_bool() {
            Ok(Self {
                callback,
                win32_event,
                wait_object,
            })
        } else {
            Err(unsafe { GetLastError() }.into())
        }
    }
}

impl Drop for Win32EventNotification {
    /// Implementing the Drop trait for the Win32EventNotification struct.
    fn drop(&mut self) {
        unsafe {
            // Deregistering the wait object.
            if !UnregisterWaitEx(self.wait_object, self.win32_event).as_bool() {
                //log::error!("error deregistering notification: {}", GetLastError);
            }
            drop(Box::from_raw(self.callback)); // Dropping the callback function.
        }

        unsafe {
            // Closing the handle to the event.
            CloseHandle(self.win32_event);
        }
    }
}

unsafe impl Send for Win32EventNotification {} // Implementing the Send trait for the Win32EventNotification struct.

/// This async function reads from the given NdisapiAdapter and handles the packets accordingly.
async fn async_read(adapter: &mut NdisapiAdapter) -> Result<()> {
    // Allocate single IntermediateBuffer on the stack.
    let mut ib = ndisapi::IntermediateBuffer::default();

    // Initialize EthPacket to pass to driver API.
    let mut packet = ndisapi::EthRequest {
        adapter_handle: adapter.adapter_handle,
        packet: ndisapi::EthPacket {
            buffer: &mut ib as *mut ndisapi::IntermediateBuffer,
        },
    };

    loop {
        // Read a packet from the adapter.
        let result = adapter.read_packet(&mut packet).await;
        if let Err(err) = result {
            println!(
                "Error reading packet. Error code = {}. Continue reading attempt.",
                err
            );
            continue;
        }

        // Print packet information.
        if ib.get_device_flags() == ndisapi::DirectionFlags::PACKET_FLAG_ON_SEND {
            println!("\nMSTCP --> Interface ({} bytes)\n", ib.get_length(),);
        } else {
            println!("\nInterface --> MSTCP ({} bytes)\n", ib.get_length(),);
        }

        // Print some information about the sliced packet.
        print_packet_info(&mut ib);

        // Re-inject the packet back into the network stack.
        if ib.get_device_flags() == ndisapi::DirectionFlags::PACKET_FLAG_ON_SEND {
            match unsafe { adapter.driver.send_packet_to_adapter(&packet) } {
                Ok(_) => {}
                Err(err) => println!("Error sending packet to adapter. Error code = {err}"),
            };
        } else {
            match unsafe { adapter.driver.send_packet_to_mstcp(&packet) } {
                Ok(_) => {}
                Err(err) => println!("Error sending packet to mstcp. Error code = {err}"),
            }
        }
    }
}

/// This async function runs the main logic of the program.
async fn main_async(adapter: &mut NdisapiAdapter) {
    // Prompts the user to press ENTER to exit.
    println!("Press ENTER to exit");

    // Initializes a channel for communication between this function and a spawned thread.
    // `tx` is the transmitter and `rx` is the receiver end of the channel.
    let (tx, rx) = oneshot::channel::<()>();

    // Spawns a new thread using Tokio's runtime, that waits for the user to press ENTER.
    tokio::spawn(async move {
        let mut line = String::new();
        std::io::stdin().read_line(&mut line).unwrap();

        // Sends a message through the channel when the user presses ENTER.
        let _ = tx.send(());
    });

    // Waits for either the server to return a result or the thread with `rx` to receive a message.
    // This is achieved by using the select! macro which polls multiple futures and blocks until one of them is ready.
    let result = tokio::select! {
        // The async_read function reads from the adapter and processes the packets.
        result = async_read(adapter) => result,
        // If the receiver end of the channel receives a message, the program prints "Shutting down..." and returns Ok(()).
        _ = rx => {
            println!("Shutting down...");
            Ok(()) // Thread returns Ok() if it receives the message successfully.
        }
    };

    // Prints any errors that may have occurred during the program's execution.
    if let Err(e) = result {
        eprintln!("Server error: {}", e);
    }
}

/// A struct representing the command line arguments.
#[derive(Parser)]
struct Cli {
    /// Network interface index (please use listadapters example to determine the right one)
    #[clap(short, long)]
    interface_index: usize,
}

// The main function of the program.
fn main() -> Result<()> {
    // Parsing command line arguments.
    let Cli {
        mut interface_index,
    } = Cli::parse();

    // Decrement interface index to match zero-based index.
    interface_index -= 1;

    // Create a new Ndisapi driver instance.
    let driver = Arc::new(
        ndisapi::Ndisapi::new("NDISRD")
            .expect("WinpkFilter driver is not installed or failed to load!"),
    );

    // Print the detected version of the Windows Packet Filter.
    println!(
        "Detected Windows Packet Filter version {}",
        driver.get_version()?
    );

    // Get a list of TCP/IP bound adapters in the system.
    let adapters = driver.get_tcpip_bound_adapters_info()?;

    // Check if the selected interface index is within the range of available interfaces.
    if interface_index + 1 > adapters.len() {
        panic!("Interface index is beyond the number of available interfaces");
    }

    // Print the name of the selected interface.
    println!("Using interface {}", adapters[interface_index].get_name(),);

    // Create a new instance of NdisapiAdapter with the selected interface.
    let mut adapter = NdisapiAdapter::new(
        Arc::clone(&driver),
        adapters[interface_index].get_handle(),
        ndisapi::FilterFlags::MSTCP_FLAG_SENT_RECEIVE_TUNNEL,
    )
    .unwrap();

    // Build a new Tokio runtime instance for executing async functions.
    let runtime = Builder::new_multi_thread()
        .worker_threads(4) // Sets the number of worker threads to 4.
        .enable_all() // Enables all optional Tokio components.
        .build()
        .unwrap();

    // Execute the main_async function using the previously defined runtime instance.
    runtime.block_on(main_async(&mut adapter));

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
