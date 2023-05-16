/// This example demonstrates the essential usage of active filtering modes for packet processing. It selects a
/// network interface and sets it into a filtering mode, where both sent and received packets are queued.
use clap::Parser;
use etherparse::{InternetSlice::*, LinkSlice::*, TransportSlice::*, *};
use ndisapi::Ndisapi;
use windows::{
    core::Result,
    Win32::Foundation::{CloseHandle, BOOLEAN, HANDLE},
    Win32::System::Threading::{
        CreateEventW, RegisterWaitForSingleObject, ResetEvent, UnregisterWaitEx, INFINITE, WT_EXECUTEINWAITTHREAD,},
};
use std::ffi::c_void;

use std::{
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll, Waker},
};
use tokio::{runtime::Builder
    , sync::oneshot};
use windows::Win32::Foundation::GetLastError;

#[derive(Parser)]
struct Cli {
    /// Network interface index (please use listadapters example to determine the right one)
    #[clap(short, long)]
    interface_index: usize,
}

// The struct NdisapiAdapter represents a network adapter with its associated driver and relevant handles.
// It also contains an optional Waker for asynchronous operations.
pub struct NdisapiAdapter{
    driver: Arc<ndisapi::Ndisapi>, // The network driver for the adapter.
    event_handle: HANDLE, // The event handle associated with the network adapter.
    adapter_handle: HANDLE, // The handle of the network adapter.
    wait_object: HANDLE, // The handle for the wait object associated with the network adapter.
    waker: Option<Waker>, // An optional Waker used for asynchronous operations.
}

// The struct ReadAdapterFuture represents a future operation for reading packets from a network adapter.
pub struct ReadAdapterFuture<'a>{
    adapter: Arc<Mutex<NdisapiAdapter>>, // A thread-safe reference-counted smart pointer wrapping the network adapter.
    packet: &'a ndisapi::EthRequest, // A reference to the request to read a packet from the network adapter.
}

// Implementing the Future trait for the ReadAdapterFuture.
impl<'a> Future for ReadAdapterFuture<'a> {
    type Output = (); // The output of the future is unit type.

    // The poll function checks if the packet read operation is ready.
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        // Lock the adapter and check if the packet read operation is ready.
        let mut adapter = self.adapter.lock().unwrap();
        if unsafe { adapter.driver.read_packet(self.packet) }.ok().is_some() {
            Poll::Ready(()) // If the packet read operation is ready, return Poll::Ready.
        } else {
            // If the packet read operation is not ready, set the waker for the current task and return Poll::Pending.
            // The waker is used to wake up the task when the packet read operation is ready.
            if adapter
                .waker
                .as_ref()
                .map_or(true, |waker| !waker.will_wake(cx.waker()))
            {
                adapter.waker = Some(cx.waker().clone());
            }
            Poll::Pending
        }
    }
}

impl<'a> ReadAdapterFuture<'a> {
    // The new function creates a new instance of ReadAdapterFuture.
    pub fn new(adapter: &AsyncNdisapiAdapter, packet: &'a ndisapi::EthRequest) -> Self {
        ReadAdapterFuture { adapter: adapter.inner(), packet } // Returns a new instance of ReadAdapterFuture.
    }
}

// Implementing methods for the NdisapiAdapter struct.
impl NdisapiAdapter {
    // The new function creates a new instance of NdisapiAdapter.
    pub fn new(driver: Arc<ndisapi::Ndisapi>, adapter_handle: HANDLE, flags: ndisapi::FilterFlags) -> NdisapiAdapter {
        let wait_object: HANDLE = HANDLE(0); // Initializing the wait object with a null handle.
        let event_handle:HANDLE;
        unsafe {
            // Creating a Win32 event without a name. The event is manual-reset and initially non-signaled.
            event_handle = CreateEventW(None, true, false, None).unwrap();
        }

        // Setting the event for packet capture for the specified adapter.
        driver.set_packet_event(adapter_handle, event_handle).unwrap();

        // Setting the operating mode for the specified adapter.
        driver.set_adapter_mode(
            adapter_handle,
            flags,
        ).unwrap();

        // Returning a new instance of NdisapiAdapter.
        NdisapiAdapter{
            driver,
            event_handle,
            adapter_handle,
            wait_object,
            waker: None
        }
    }
}

// Implementing the Drop trait for the NdisapiAdapter struct.
// The drop method will be called automatically when the NdisapiAdapter object goes out of scope.
impl Drop for NdisapiAdapter {
    fn drop(&mut self) {
        unsafe {
            // Closing the handle to the event when the NdisapiAdapter object is dropped.
            CloseHandle(self.event_handle);
        }
    }
}

// This struct represents an asynchronous version of the NdisapiAdapter struct.
// It's wrapped in an Arc and a Mutex for thread safety and reference counting.
#[derive(Clone)]
pub struct AsyncNdisapiAdapter(Arc<Mutex<NdisapiAdapter>>);

impl AsyncNdisapiAdapter {
    // The new function creates a new instance of AsyncNdisapiAdapter.
    // It registers a wait for a single object, which allows the program to be notified when the event is signaled.
    pub fn new(adapter: NdisapiAdapter) -> Result<Self> {
        // Create a new Arc<Mutex<NdisapiAdapter>>.
        let adapter = Self(Arc::new(Mutex::new(adapter)));
        let mut wait_object: HANDLE = HANDLE(0);
        let rc = {
            let ndisapi_adapter = adapter.0.lock().unwrap();
            unsafe {
                RegisterWaitForSingleObject(
                    &mut wait_object,
                    ndisapi_adapter.event_handle,
                    Some(AsyncNdisapiAdapter::callback),
                    Some(Arc::into_raw(adapter.inner()) as *const c_void),
                    INFINITE,
                    WT_EXECUTEINWAITTHREAD,
                )
            }
        };

        // Check if the registration was successful.
        if rc.as_bool() {
            Ok(adapter)
        } else {
            Err(unsafe { GetLastError() }.into())
        }
    }

    // This method returns a clone of the Arc<Mutex<NdisapiAdapter>>.
    pub fn inner(&self) -> Arc<Mutex<NdisapiAdapter>> {
        Arc::clone(&self.0)
    }

    // This method creates a new instance of ReadAdapterFuture for reading packets from the adapter.
    fn async_read_packet<'a>(&self, packet: &'a ndisapi::EthRequest) -> ReadAdapterFuture<'a> {
        ReadAdapterFuture::new(self, packet)
    }

    // The callback function for the registered wait.
    // It's called when the event associated with the adapter is signaled.
    unsafe extern "system" fn callback(param0: *mut c_void, _: BOOLEAN) {
        println!("Event callback has been called");

        // Recover the Arc<Mutex<NdisapiAdapter>> from the raw pointer.
        let adapter_ptr = unsafe {
            let arc_ptr: *const Mutex<NdisapiAdapter> = param0 as *const Mutex<NdisapiAdapter>;
            Arc::increment_strong_count(arc_ptr);
            Arc::from_raw(arc_ptr)
        };

        // Lock the adapter and reset the event.
        let mut adapter = adapter_ptr.lock().unwrap();
        unsafe { ResetEvent(adapter.event_handle) };

        // If a waker is present, wake it up.
        if let Some(waker) = adapter.waker.take() {
            waker.wake()
        }
    }
}

// Implementing the Drop trait for the AsyncNdisapiAdapter struct.
// The drop method will be called automatically when the AsyncNdisapiAdapter object goes out of scope.
impl Drop for AsyncNdisapiAdapter {
    fn drop(&mut self) {
        // Lock the adapter and unregister the wait for the single object if it's not a null handle.
        {
            let ndis_adapter = self.0.lock().unwrap();
            unsafe {
                if ndis_adapter.wait_object != HANDLE(0) {
                    UnregisterWaitEx(ndis_adapter.wait_object, HANDLE(0));
                }
            }
        }

        // Get the inner Arc<Mutex<NdisapiAdapter>> of the AsyncNdisapiAdapter.
        let adapter = self.inner();

        // Decrement the strong count of the Arc twice.
        // This is done because the Arc was cloned when the wait was registered, and again when the callback was called.
        unsafe {
            let arc_ptr = Arc::into_raw(adapter);
            Arc::decrement_strong_count(arc_ptr);
            Arc::decrement_strong_count(arc_ptr);
        }

        // Print the remaining strong count of the Arc.
        // It should be 0, because all strong references should have been dropped at this point.
        println!("Strong count = {}", Arc::strong_count(&self.0))
    }
}


// This async function reads from the given AsyncNdisapiAdapter and handles the packets accordingly.
async fn async_read(adapter: &AsyncNdisapiAdapter) -> Result<()> {

    // Declare the variables that will hold the driver and adapter handle.
    let driver: Arc<Ndisapi>;
    let adapter_handle: HANDLE;
    
    // Lock the adapter to access its data.
    {
        let adapter = adapter.inner();
        let ndis_adapter = adapter.lock().unwrap();
        driver = ndis_adapter.driver.clone();
        adapter_handle = ndis_adapter.adapter_handle;
    }

    // Allocate single IntermediateBuffer on the stack.
    let mut ib = ndisapi::IntermediateBuffer::default();

    // Initialize EthPacket to pass to driver API.
    let packet = ndisapi::EthRequest {
        adapter_handle,
        packet: ndisapi::EthPacket {
            buffer: &mut ib as *mut ndisapi::IntermediateBuffer,
        },
    };

    loop {
        // Read a packet from the adapter.
        adapter.async_read_packet(&packet).await;

        // Print packet information.
        if ib.get_device_flags() == ndisapi::DirectionFlags::PACKET_FLAG_ON_SEND {
            println!(
                "\nMSTCP --> Interface ({} bytes)\n",
                ib.get_length(),
            );
        } else {
            println!(
                "\nInterface --> MSTCP ({} bytes)\n",
                ib.get_length(),
            );
        }

        // Print some information about the sliced packet.
        print_packet_info(&mut ib);

        // Re-inject the packet back into the network stack.
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
    }
}

// This async function runs the main logic of the program.
async fn main_async(adapter: &AsyncNdisapiAdapter) {
    
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

// The main function of the program.
fn main() -> Result<()> {
    // Parsing command line arguments.
    let Cli {
        mut interface_index,
    } = Cli::parse();

    // Decrement interface index to match zero-based index.
    interface_index -= 1;

    // Create a new Ndisapi driver instance.
    let driver = Arc::new(ndisapi::Ndisapi::new("NDISRD")
        .expect("WinpkFilter driver is not installed or failed to load!"));

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
    println!(
        "Using interface {}",
        adapters[interface_index].get_name(),
    );

    // Create a new instance of AsyncNdisapiAdapter with the selected interface.
    let adapter = AsyncNdisapiAdapter::new(NdisapiAdapter::new(Arc::clone(&driver), adapters[interface_index].get_handle(),  ndisapi::FilterFlags::MSTCP_FLAG_SENT_RECEIVE_TUNNEL)).unwrap();

    // Build a new Tokio runtime instance for executing async functions.
    let runtime = Builder::new_multi_thread()
        .worker_threads(4) // Sets the number of worker threads to 4.
        .enable_all() // Enables all optional Tokio components.
        .build()
        .unwrap();
    
    // Execute the main_async function using the previously defined runtime instance.
    runtime.block_on(main_async(&adapter));

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
