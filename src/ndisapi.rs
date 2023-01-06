use std::{
    ffi::c_uint,
    mem::{size_of, MaybeUninit},
};

use windows::{
    core::Result,
    Win32::Foundation::{CloseHandle, GetLastError, HANDLE},
    Win32::Storage::FileSystem::{
        CreateFileW, FILE_ACCESS_FLAGS, FILE_FLAG_OVERLAPPED, FILE_SHARE_READ, FILE_SHARE_WRITE,
        OPEN_EXISTING,
    },
    Win32::System::IO::DeviceIoControl,
};

pub use crate::driver::*;

pub struct Ndisapi {
    driver_handle: HANDLE,
}

pub struct NetworkAdapterInfo {
    name: String,
    handle: HANDLE,
    medium: u32,
    hw_address: [u8; 6],
    mtu: u16,
}

impl NetworkAdapterInfo {
    fn new(name: String, handle: HANDLE, medium: u32, hw_address: [u8; 6], mtu: u16) -> Self {
        Self {
            name,
            handle,
            medium,
            hw_address,
            mtu,
        }
    }

    pub fn get_name(&self) -> &str {
        &self.name
    }

    pub fn get_handle(&self) -> HANDLE {
        self.handle
    }

    pub fn get_medium(&self) -> u32 {
        self.medium
    }

    pub fn get_hw_address(&self) -> &[u8; 6] {
        &self.hw_address
    }

    pub fn get_mtu(&self) -> u16 {
        self.mtu
    }
}

impl Drop for Ndisapi {
    fn drop(&mut self) {
        if !self.driver_handle.is_invalid() {
            unsafe {
                CloseHandle(self.driver_handle);
            }
        }
    }
}

impl Ndisapi {
    pub fn get_tcpip_bound_adapters_info(&self) -> Result<Vec<NetworkAdapterInfo>> {
        let mut adapters: MaybeUninit<driver::TcpAdapterList> = ::std::mem::MaybeUninit::uninit();

        let result = unsafe {
            DeviceIoControl(
                self.driver_handle,
                driver::IOCTL_NDISRD_GET_TCPIP_INTERFACES,
                Some(adapters.as_mut_ptr() as _),
                size_of::<driver::TcpAdapterList>() as u32,
                Some(adapters.as_mut_ptr() as _),
                size_of::<driver::TcpAdapterList>() as u32,
                None,
                None,
            )
        };

        if result.as_bool() {
            let mut result = Vec::new();
            let adapters = unsafe { adapters.assume_init() };

            for i in 0..adapters.adapter_count as usize {
                let next = NetworkAdapterInfo::new(
                    String::from_utf8(adapters.adapter_name_list[i].to_vec()).unwrap(),
                    adapters.adapter_handle[i],
                    adapters.adapter_medium_list[i],
                    adapters.current_address[i],
                    adapters.mtu[i],
                );
                result.push(next);
            }
            Ok(result)
        } else {
            Err(unsafe { GetLastError() }.into())
        }
    }

    pub fn get_version(&self) -> Result<(u32, u32, u32)> {
        let mut version = u32::MAX;

        let result = unsafe {
            DeviceIoControl(
                self.driver_handle,
                driver::IOCTL_NDISRD_GET_VERSION,
                Some(&mut version as *mut c_uint as _),
                size_of::<u32>() as u32,
                Some(&mut version as *mut c_uint as _),
                size_of::<u32>() as u32,
                None,
                None,
            )
        };

        if !result.as_bool() {
            Err(unsafe { GetLastError() }.into())
        } else {
            Ok((
                (version & (0xF000)) >> 12,
                (version & (0xFF000000)) >> 24,
                (version & (0xFF0000)) >> 16,
            ))
        }
    }

    pub fn new<P>(filename: P) -> Result<Self>
    where
        P: ::std::convert::Into<::windows::core::PCWSTR>,
    {
        if let Ok(handle) = unsafe {
            CreateFileW(
                filename,
                FILE_ACCESS_FLAGS(0u32),
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                None,
                OPEN_EXISTING,
                FILE_FLAG_OVERLAPPED,
                None,
            )
        } {
            Ok(Self {
                driver_handle: handle,
            })
        } else {
            Err(unsafe { GetLastError() }.into())
        }
    }

    pub fn read_packet(
        &self,
        adapter_handle: HANDLE,
        packet: &mut driver::EthPacket,
    ) -> Result<()> {
        let eth_request = driver::EthRequest {
            adapter_handle,
            packet: *packet,
        };

        let result = unsafe {
            DeviceIoControl(
                self.driver_handle,
                driver::IOCTL_NDISRD_READ_PACKET,
                Some(&eth_request as *const driver::EthRequest as *const std::ffi::c_void),
                size_of::<driver::EthRequest>() as u32,
                Some(&eth_request as *const driver::EthRequest as *mut std::ffi::c_void),
                size_of::<driver::EthRequest>() as u32,
                None,
                None,
            )
        };

        if !result.as_bool() {
            Err(unsafe { GetLastError() }.into())
        } else {
            Ok(())
        }
    }

    pub fn read_packets<'a, T: Iterator<Item = &'a mut driver::EthPacket>, const N: usize>(
        &self,
        adapter_handle: HANDLE,
        mut packets: T,
    ) -> Result<usize> {
        let mut eth_request = driver::EthMRequest::new(adapter_handle);

        for (i, packet) in packets.enumerate() {
            eth_request.packets[i] = *packet;
            eth_request.packet_number += 1;
        }

        let result = unsafe {
            DeviceIoControl(
                self.driver_handle,
                driver::IOCTL_NDISRD_READ_PACKETS,
                Some(&eth_request as *const driver::EthMRequest<N> as *const std::ffi::c_void),
                size_of::<driver::EthMRequest<N>>() as u32,
                Some(&eth_request as *const driver::EthMRequest<N> as *mut std::ffi::c_void),
                size_of::<driver::EthMRequest<N>>() as u32,
                None,
                None,
            )
        };

        if result.as_bool() {
            Ok(eth_request.packet_success as usize)
        } else {
            Err(unsafe { GetLastError() }.into())
        }
    }

    pub fn send_packet_to_adapter(
        &self,
        adapter_handle: HANDLE,
        packet: &mut driver::EthPacket,
    ) -> Result<()> {
        let eth_request = driver::EthRequest {
            adapter_handle,
            packet: *packet,
        };

        let result = unsafe {
            DeviceIoControl(
                self.driver_handle,
                driver::IOCTL_NDISRD_SEND_PACKET_TO_ADAPTER,
                Some(&eth_request as *const driver::EthRequest as *const std::ffi::c_void),
                size_of::<driver::EthRequest>() as u32,
                None,
                0,
                None,
                None,
            )
        };

        if !result.as_bool() {
            Err(unsafe { GetLastError() }.into())
        } else {
            Ok(())
        }
    }

    pub fn send_packet_to_mstcp(
        &self,
        adapter_handle: HANDLE,
        packet: &mut driver::EthPacket,
    ) -> Result<()> {
        let eth_request = driver::EthRequest {
            adapter_handle,
            packet: *packet,
        };

        let result = unsafe {
            DeviceIoControl(
                self.driver_handle,
                driver::IOCTL_NDISRD_SEND_PACKET_TO_MSTCP,
                Some(&eth_request as *const driver::EthRequest as *const std::ffi::c_void),
                size_of::<driver::EthRequest>() as u32,
                None,
                0,
                None,
                None,
            )
        };

        if !result.as_bool() {
            Err(unsafe { GetLastError() }.into())
        } else {
            Ok(())
        }
    }

    pub fn send_packets_to_mstcp<
        'a,
        T: Iterator<Item = &'a mut driver::EthPacket>,
        const N: usize,
    >(
        &self,
        adapter_handle: HANDLE,
        mut packets: T,
    ) -> Result<()> {
        let mut eth_request = driver::EthMRequest::new(adapter_handle);

        for (i, packet) in packets.enumerate() {
            eth_request.packets[i] = *packet;
            eth_request.packet_number += 1;
        }

        let result = unsafe {
            DeviceIoControl(
                self.driver_handle,
                driver::IOCTL_NDISRD_SEND_PACKETS_TO_MSTCP,
                Some(&eth_request as *const driver::EthMRequest<N> as *const std::ffi::c_void),
                size_of::<driver::EthMRequest<N>>() as u32,
                None,
                0,
                None,
                None,
            )
        };

        if !result.as_bool() {
            Err(unsafe { GetLastError() }.into())
        } else {
            Ok(())
        }
    }

    pub fn send_packets_to_adapter<
        'a,
        T: Iterator<Item = &'a mut driver::EthPacket>,
        const N: usize,
    >(
        &self,
        adapter_handle: HANDLE,
        mut packets: T,
    ) -> Result<()> {
        let mut eth_request = driver::EthMRequest::new(adapter_handle);

        for (i, packet) in packets.enumerate() {
            eth_request.packets[i] = *packet;
            eth_request.packet_number += 1;
        }

        let result = unsafe {
            DeviceIoControl(
                self.driver_handle,
                driver::IOCTL_NDISRD_SEND_PACKETS_TO_ADAPTER,
                Some(&eth_request as *const driver::EthMRequest<N> as *const std::ffi::c_void),
                size_of::<driver::EthMRequest<N>>() as u32,
                None,
                0,
                None,
                None,
            )
        };

        if !result.as_bool() {
            Err(unsafe { GetLastError() }.into())
        } else {
            Ok(())
        }
    }

    pub fn set_adapter_mode(&self, adapter_handle: HANDLE, flags: u32) -> Result<()> {
        let adapter_mode = driver::AdapterMode {
            adapter_handle,
            flags,
        };

        let result = unsafe {
            DeviceIoControl(
                self.driver_handle,
                driver::IOCTL_NDISRD_SET_ADAPTER_MODE,
                Some(&adapter_mode as *const driver::AdapterMode as *const std::ffi::c_void),
                size_of::<driver::AdapterMode>() as u32,
                None,
                0,
                None,
                None,
            )
        };

        if !result.as_bool() {
            Err(unsafe { GetLastError() }.into())
        } else {
            Ok(())
        }
    }

    pub fn set_packet_event(&self, adapter_handle: HANDLE, event_handle: HANDLE) -> Result<()> {
        let adapter_event = driver::AdapterEvent {
            adapter_handle,
            event_handle,
        };

        let result = unsafe {
            DeviceIoControl(
                self.driver_handle,
                driver::IOCTL_NDISRD_SET_EVENT,
                Some(&adapter_event as *const driver::AdapterEvent as *const std::ffi::c_void),
                size_of::<driver::AdapterEvent>() as u32,
                None,
                0,
                None,
                None,
            )
        };

        if !result.as_bool() {
            Err(unsafe { GetLastError() }.into())
        } else {
            Ok(())
        }
    }
}
