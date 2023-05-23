use clap::Parser;
use etherparse::{InternetSlice::*, LinkSlice::*, TransportSlice::*, *};
use futures::{task::AtomicWaker, Future};
use ndisapi::{EthPacket, FilterFlags};
use std::{
    ffi::c_void,
    pin::Pin,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    task::{Context, Poll},
};
use tokio::sync::oneshot;
use windows::{
    core::Result,
    Win32::{
        Foundation::{CloseHandle, GetLastError, BOOLEAN, HANDLE},
        System::Threading::{
            CreateEventW, RegisterWaitForSingleObject, ResetEvent, UnregisterWaitEx, INFINITE,
            WT_EXECUTEINWAITTHREAD,
        },
    },
};

/// The struct NdisapiAdapter represents a network adapter with its associated driver and relevant handles.
pub struct NdisapiAdapter {
    /// The network driver for the adapter.
    driver: Arc<ndisapi::Ndisapi>,
    /// The handle of the network adapter.
    adapter_handle: HANDLE,
    /// A future that resolves when a Win32 event is signaled.
    notif: Win32EventFuture,
}

impl NdisapiAdapter {
    /// Constructs a new `NdisapiAdapter`.
    ///
    /// This function takes a network driver and the handle of the network adapter as arguments.
    /// It then creates a Win32 event and sets it for packet capture for the specified adapter.
    /// Finally, it creates a new `NdisapiAdapter` with the driver, adapter handle, and a
    /// `Win32EventFuture` created with the event handle.
    ///
    /// # Arguments
    ///
    /// * `driver` - An `Arc<ndisapi::Ndisapi>` that represents the network driver for the adapter.
    /// * `adapter_handle` - A `HANDLE` that represents the handle of the network adapter.
    ///
    /// # Safety
    ///
    /// This function contains unsafe code blocks due to the FFI call to `CreateEventW`
    /// and the potential for a null or invalid adapter handle. The caller should ensure that
    /// the passed network driver and the adapter handle are properly initialized and safe
    /// to use in this context.
    ///
    /// # Errors
    ///
    /// Returns an error if the Win32 event creation fails, or if setting the packet capture event for
    /// the adapter fails, or if creating the `Win32EventFuture` fails.
    ///
    /// # Returns
    ///
    /// Returns an `Ok(Self)` if the `NdisapiAdapter` is successfully created, where `Self` is
    /// the newly created `NdisapiAdapter`.
    pub fn new(
        driver: Arc<ndisapi::Ndisapi>, // The network driver for the adapter.
        adapter_handle: HANDLE,        // The handle of the network adapter.
    ) -> Result<Self> {
        let event_handle = unsafe {
            // Creating a Win32 event without a name. The event is manual-reset and initially non-signaled.
            CreateEventW(None, true, false, None)?
        };

        // Setting the event for packet capture for the specified adapter.
        driver.set_packet_event(adapter_handle, event_handle)?;

        Ok(Self {
            adapter_handle,
            driver,
            notif: Win32EventFuture::new(event_handle)?, // Creating a new Win32EventFuture with the event handle.
        })
    }

    /// Sets the operating mode for the network adapter.
    ///
    /// This function takes a set of `FilterFlags` as an argument which represent the desired
    /// operating mode, and applies them to the network adapter.
    ///
    /// # Arguments
    ///
    /// * `flags` - `FilterFlags` that represent the desired operating mode for the network adapter.
    ///
    /// # Errors
    ///
    /// Returns an error if the driver fails to set the operating mode for the network adapter.
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if the operating mode was successfully set for the network adapter.
    pub fn set_adapter_mode(&self, flags: FilterFlags) -> Result<()> {
        self.driver.set_adapter_mode(self.adapter_handle, flags)?;
        Ok(())
    }

    /// Reads a packet from the network adapter asynchronously and returns it as an `EthPacket`.
    ///
    /// This function initializes an `EthRequest` with the provided `EthPacket` and the handle to the adapter.
    /// Then it attempts to read a packet from the network adapter. If the read operation fails,
    /// the function awaits for a packet event before attempting the read operation again.
    ///
    /// # Arguments
    ///
    /// * `packet` - An `EthPacket` which will be filled with the data from the network adapter.
    ///
    /// # Safety
    ///
    /// This function contains unsafe code blocks due to the FFI calls to `driver.read_packet(&request)`
    /// and the call to `GetLastError()`. Ensure the passed `EthPacket` is properly initialized
    /// and safe to use in this context.
    ///
    /// The function also temporarily pins the `Win32EventFuture` instance to the stack with `Pin::new(&mut self.notif).await`.
    /// While this is generally considered safe because `Win32EventFuture` and its internals do not move after being pinned,
    /// and because the poll function does not invalidate or move these internals after pinning, any future changes to `Win32EventFuture` or its poll
    /// implementation could potentially make this unsafe. Therefore, be sure to review these aspects if you modify `Win32EventFuture` or this function in the future.
    ///
    /// # Errors
    ///
    /// Returns an error if the driver fails to read a packet from the network adapter, or if the
    /// await operation on the packet event fails. The specific error returned in the first case is the
    /// last error occurred, obtained via a call to `GetLastError()`.
    ///
    /// # Returns
    ///
    /// Returns an `Ok(EthPacket)` if the packet is successfully read from the network adapter,
    /// where `EthPacket` is the original packet filled with the data from the network adapter.
    pub async fn read_packet(&mut self, packet: EthPacket) -> Result<EthPacket> {
        let driver = self.driver.clone();

        // Initialize EthPacket to pass to driver API.
        let request = ndisapi::EthRequest {
            adapter_handle: self.adapter_handle,
            packet,
        };

        // first try to read packet
        if unsafe { driver.read_packet(&request) }.is_ok() {
            return Ok(packet);
        }

        let result = Pin::new(&mut self.notif).await; // wait for packet event

        match result {
            Ok(_) => {
                if unsafe { driver.read_packet(&request) }.ok().is_some() {
                    Ok(packet)
                } else {
                    Err(unsafe { GetLastError() }.into())
                }
            }
            Err(e) => Err(e),
        }
    }

    /// Sends an Ethernet packet to the network adapter.
    ///
    /// This function takes an `EthPacket` as an argument and passes it to the network adapter.
    /// This is achieved by creating an `EthRequest` structure which contains the `EthPacket`
    /// and the handle to the adapter, and then passing this request to the driver API.
    ///
    /// # Arguments
    ///
    /// * `packet` - An `EthPacket` that represents the Ethernet packet to be sent.
    ///
    /// # Safety
    ///
    /// This function is marked unsafe due to the FFI call to `self.driver.send_packet_to_adapter(&request)`
    /// and the call to `GetLastError()`. Caller should ensure that the passed `EthPacket` is properly
    /// initialized and safe to use in this context.
    ///
    /// # Errors
    ///
    /// Returns an error if the driver fails to send the packet to the network adapter. The specific error
    /// returned is the last error occurred, obtained via a call to `GetLastError()`.
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if the packet was successfully sent to the network adapter.
    pub fn send_packet_to_adapter(&self, packet: EthPacket) -> Result<()> {
        // Initialize EthPacket to pass to driver API.
        let request = ndisapi::EthRequest {
            adapter_handle: self.adapter_handle,
            packet,
        };

        // Try to send packet to the network adapter.
        if unsafe { self.driver.send_packet_to_adapter(&request) }.is_ok() {
            Ok(())
        } else {
            Err(unsafe { GetLastError() }.into())
        }
    }

    /// Sends an Ethernet packet upwards the network stack to the Microsoft TCP/IP protocol driver.
    ///
    /// This function takes an `EthPacket` as an argument and sends it upwards the network stack.
    /// This is accomplished by creating an `EthRequest` structure which contains the `EthPacket`
    /// and the handle to the adapter, and then passing this request to the driver API.
    ///
    /// # Arguments
    ///
    /// * `packet` - An `EthPacket` that represents the Ethernet packet to be sent.
    ///
    /// # Safety
    ///
    /// This function is marked unsafe due to the FFI call to `self.driver.send_packet_to_mstcp(&request)`
    /// and the call to `GetLastError()`. Ensure that the passed `EthPacket` is properly initialized
    /// and safe to use in this context.
    ///
    /// # Errors
    ///
    /// Returns an error if the driver fails to send the packet upwards the network stack. The specific error
    /// returned is the last error occurred, obtained via a call to `GetLastError()`.
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if the packet was successfully sent upwards the network stack.
    pub fn send_packet_to_mstcp(&self, packet: EthPacket) -> Result<()> {
        // Initialize EthPacket to pass to driver API.
        let request = ndisapi::EthRequest {
            adapter_handle: self.adapter_handle,
            packet,
        };

        // Try to send packet upwards the network stack.
        if unsafe { self.driver.send_packet_to_mstcp(&request) }.is_ok() {
            Ok(())
        } else {
            Err(unsafe { GetLastError() }.into())
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
        _ = self
            .driver
            .set_packet_event(self.adapter_handle, HANDLE(0isize));
    }
}

/// A future that resolves when a Win32 event is signaled.
struct Win32EventFuture {
    #[allow(dead_code)]
    notif: Win32EventNotification, // The Win32 event notification object.
    waker: Arc<AtomicWaker>, // An atomic waker for waking the future.
    ready: Arc<AtomicBool>,  // An atomic boolean indicating whether the event is ready.
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

/// Implementing the Debug trait for the Win32EventNotification struct.
impl std::fmt::Debug for Win32EventNotification {
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
        let mut wait_object: HANDLE = HANDLE(0isize);

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
            drop(unsafe { Box::from_raw(callback) }); // Dropping the callback function.
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

/// # Safety
/// `Win32EventNotification` is safe to send between threads because it does not
/// encompass any thread-specific data (like `std::rc::Rc` or `std::cell::RefCell`)
/// and does not provide mutable access to its data across different threads
/// (like `std::sync::Arc`).
/// The Windows API functions that we're using (`RegisterWaitForSingleObject`,
/// `UnregisterWaitEx`, and `CloseHandle`) are all thread-safe as per the
/// Windows API documentation. Our struct only contains raw pointers and handles
/// that are essentially IDs which can be freely copied and are not tied to a
/// specific thread. As such, it's safe to implement Send for this type.
unsafe impl Send for Win32EventNotification {}

/// This async function reads from the given NdisapiAdapter and handles the packets accordingly.
async fn async_read(adapter: &mut NdisapiAdapter) -> Result<()> {
    // Set the adapter mode to MSTCP_FLAG_SENT_RECEIVE_TUNNEL.
    adapter.set_adapter_mode(ndisapi::FilterFlags::MSTCP_FLAG_SENT_RECEIVE_TUNNEL)?;

    // Allocate single IntermediateBuffer on the stack.
    let mut ib = ndisapi::IntermediateBuffer::default();

    // Initialize EthPacket to pass to driver API.
    let packet = ndisapi::EthPacket {
        buffer: &mut ib as *mut ndisapi::IntermediateBuffer,
    };

    loop {
        // Read a packet from the adapter.
        let result = adapter.read_packet(packet).await;
        if let Err(err) = result {
            println!(
                "Error reading packet. Error code = {}. Continue reading.",
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
            match adapter.send_packet_to_adapter(packet) {
                Ok(_) => {}
                Err(err) => println!("Error sending packet to adapter. Error code = {err}"),
            };
        } else {
            match adapter.send_packet_to_mstcp(packet) {
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
#[tokio::main]
async fn main() -> Result<()> {
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
    let mut adapter =
        NdisapiAdapter::new(Arc::clone(&driver), adapters[interface_index].get_handle()).unwrap();

    // Execute the main_async function using the previously defined adapter.
    main_async(&mut adapter).await;
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
