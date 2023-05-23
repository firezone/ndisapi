//! # Submodule: Win32EventFuture
//!
//! The submodule contains two main structures: `Win32EventFuture` and `Win32EventNotification`. 
//! These types are used to interface with the Win32 API for event-driven asynchronous programming.
//!
//! `Win32EventFuture` represents a future that resolves when a specific Win32 event is signaled. 
//! It encapsulates a `Win32EventNotification` object (the Win32 event notification object), 
//! an `AtomicWaker` (used to wake up the future when it's ready to make progress), 
//! and an `AtomicBool` (indicating whether the event is ready or not). 
//!
//! An instance of `Win32EventFuture` can be created with a given Win32 event handle, 
//! and can be polled to check if the packet event is ready.
//!
//! The `Win32EventFuture` struct implements the `Future` trait, making it possible to use 
//! it with async/await syntax and within other futures or async functions.
//!
//! `Win32EventNotification` encapsulates a Win32 event and provides a mechanism to register 
//! a callback function that is called when the event is signaled. It maintains the Win32 event handle, 
//! the wait object handle, and a pointer to the callback function. It also implements the `Drop` trait 
//! to ensure proper cleanup of its resources when it goes out of scope.
//!
//! This submodule provides an abstraction over the Win32 event handling mechanism, providing a Rust-friendly, 
//! safe, and idiomatic way to work with Win32 events in an asynchronous context. 
//! This can be especially useful in scenarios involving network I/O, inter-process communication, 
//! or any other situation where you need to wait for an event to occur without blocking your application.
use futures::{task::AtomicWaker, Future};
use std::{
    ffi::c_void,
    pin::Pin,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    task::{Context, Poll},
};
use windows::{
    core::Result,
    Win32::{
        Foundation::{CloseHandle, GetLastError, BOOLEAN, HANDLE},
        System::Threading::{
            RegisterWaitForSingleObject, ResetEvent, UnregisterWaitEx, INFINITE,
            WT_EXECUTEINWAITTHREAD,
        },
    },
};

/// A future that resolves when a Win32 event is signaled.
pub struct Win32EventFuture {
    #[allow(dead_code)]
    /// The Win32 event notification object.
    notif: Win32EventNotification, 
    /// An atomic waker for waking the future.
    waker: Arc<AtomicWaker>, 
    /// An atomic boolean indicating whether the event is ready.
    ready: Arc<AtomicBool>,  
}

impl Win32EventFuture {
    /// Create a new `Win32EventFuture` instance with the specified event handle.
    pub fn new(event_handle: HANDLE) -> Result<Self> {
        let waker = Arc::new(AtomicWaker::new());
        let ready = Arc::new(AtomicBool::new(false));

        Ok(Self {
            waker: waker.clone(),
            ready: ready.clone(),
            notif: Win32EventNotification::new(
                event_handle,
                Box::new(move |_| {
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
