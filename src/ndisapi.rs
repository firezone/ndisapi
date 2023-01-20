use std::mem::{size_of, MaybeUninit};

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

const OID_GEN_CURRENT_PACKET_FILTER: u32 = 0x0001010E;

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
        unsafe {
            CloseHandle(self.driver_handle);
        }
    }
}

impl Ndisapi {
    /// Adds Secondary Fast I/O shared memory section
    pub fn add_secondary_fast_io<const N: usize>(
        &self,
        fast_io_section: &mut FastIoSection<N>,
    ) -> Result<()> {
        let params = InitializeFastIoParams::<N> {
            header_ptr: fast_io_section as *mut FastIoSection<N>,
            data_size: N as u32,
        };

        let result = unsafe {
            DeviceIoControl(
                self.driver_handle,
                IOCTL_NDISRD_ADD_SECOND_FAST_IO_SECTION,
                Some(&params as *const InitializeFastIoParams<N> as *const std::ffi::c_void),
                size_of::<InitializeFastIoParams<N>>() as u32,
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

    /// Flushes the packet queue in the NDIS filter driver for the requested interface.
    pub fn flush_adapter_packet_queue(&self, adapter_handle: HANDLE) -> Result<()> {
        let result = unsafe {
            DeviceIoControl(
                self.driver_handle,
                IOCTL_NDISRD_FLUSH_ADAPTER_QUEUE,
                Some(&adapter_handle as *const HANDLE as *const std::ffi::c_void),
                size_of::<HANDLE>() as u32,
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

    /// Queries the packet filter mode for the selected network interface
    pub fn get_adapter_mode(&self, adapter_handle: HANDLE) -> Result<FilterFlags> {
        let mut adapter_mode = AdapterMode {
            adapter_handle,
            ..Default::default()
        };

        let result = unsafe {
            DeviceIoControl(
                self.driver_handle,
                IOCTL_NDISRD_GET_ADAPTER_MODE,
                Some(&adapter_mode as *const AdapterMode as *const std::ffi::c_void),
                size_of::<AdapterMode>() as u32,
                Some(&mut adapter_mode as *mut AdapterMode as *mut std::ffi::c_void),
                size_of::<AdapterMode>() as u32,
                None,
                None,
            )
        };

        if !result.as_bool() {
            Err(unsafe { GetLastError() }.into())
        } else {
            Ok(adapter_mode.flags)
        }
    }

    /// Queries the adapter packet queue size for the given adapter handle
    pub fn get_adapter_packet_queue_size(&self, adapter_handle: HANDLE) -> Result<u32> {
        let mut queue_size = 0u32;

        let result = unsafe {
            DeviceIoControl(
                self.driver_handle,
                IOCTL_NDISRD_ADAPTER_QUEUE_SIZE,
                Some(&adapter_handle as *const HANDLE as *const std::ffi::c_void),
                size_of::<HANDLE>() as u32,
                Some(&mut queue_size as *mut u32 as *mut std::ffi::c_void),
                size_of::<u32>() as u32,
                None,
                None,
            )
        };

        if !result.as_bool() {
            Err(unsafe { GetLastError() }.into())
        } else {
            Ok(queue_size)
        }
    }

    /// Queries current hardware packet filter (OID_GEN_CURRENT_PACKET_FILTER) for the specified network interface
    pub fn get_hw_packet_filter(&self, adapter_handle: HANDLE) -> Result<u32> {
        let mut oid = PacketOidData::new(adapter_handle, OID_GEN_CURRENT_PACKET_FILTER, 0u32);

        self.ndis_get_request::<_>(&mut oid)?;

        Ok(oid.data)
    }

    /// Queries static filter table from the NDIS filter driver
    pub fn get_packet_filter_table<const N: usize>(
        &self,
        filter_table: &mut StaticFilterTable<N>,
    ) -> Result<()> {
        let result = unsafe {
            DeviceIoControl(
                self.driver_handle,
                IOCTL_NDISRD_GET_PACKET_FILTERS,
                None,
                0,
                Some(filter_table as *mut StaticFilterTable<N> as *mut std::ffi::c_void),
                size_of::<StaticFilterTable<N>>() as u32,
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

    /// Queries static filter table from the NDIS filter driver and resets the filter statistics
    pub fn get_packet_filter_table_reset_stats<const N: usize>(
        &self,
        filter_table: &mut StaticFilterTable<N>,
    ) -> Result<()> {
        let result = unsafe {
            DeviceIoControl(
                self.driver_handle,
                IOCTL_NDISRD_GET_PACKET_FILTERS_RESET_STATS,
                None,
                0,
                Some(filter_table as *mut StaticFilterTable<N> as *mut std::ffi::c_void),
                size_of::<StaticFilterTable<N>>() as u32,
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

    /// Queries static filter table size from the NDIS filter driver
    pub fn get_packet_filter_table_size(&self) -> Result<usize> {
        let mut size = 0u32;

        let result = unsafe {
            DeviceIoControl(
                self.driver_handle,
                IOCTL_NDISRD_GET_PACKET_FILTERS_TABLESIZE,
                None,
                0,
                Some(&mut size as *mut u32 as *mut std::ffi::c_void),
                size_of::<u32>() as u32,
                None,
                None,
            )
        };

        if !result.as_bool() {
            Err(unsafe { GetLastError() }.into())
        } else {
            Ok(size as usize)
        }
    }

    /// Queries the information about active WAN connections from the NDIS filter driver.
    pub fn get_ras_links(&self, ras_links: &mut RasLinks) -> Result<()> {
        let result = unsafe {
            DeviceIoControl(
                self.driver_handle,
                IOCTL_NDISRD_GET_RAS_LINKS,
                Some(ras_links as *const RasLinks as *const std::ffi::c_void),
                size_of::<RasLinks>() as u32,
                Some(ras_links as *const RasLinks as *mut std::ffi::c_void),
                size_of::<RasLinks>() as u32,
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

    /// Queries information on available network interfaces
    pub fn get_tcpip_bound_adapters_info(&self) -> Result<Vec<NetworkAdapterInfo>> {
        let mut adapters: MaybeUninit<TcpAdapterList> = ::std::mem::MaybeUninit::uninit();

        let result = unsafe {
            DeviceIoControl(
                self.driver_handle,
                IOCTL_NDISRD_GET_TCPIP_INTERFACES,
                Some(adapters.as_mut_ptr() as _),
                size_of::<TcpAdapterList>() as u32,
                Some(adapters.as_mut_ptr() as _),
                size_of::<TcpAdapterList>() as u32,
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

    /// Queries NDIS filter driver version
    pub fn get_version(&self) -> Result<(u32, u32, u32)> {
        let mut version = u32::MAX;

        let result = unsafe {
            DeviceIoControl(
                self.driver_handle,
                IOCTL_NDISRD_GET_VERSION,
                Some(&mut version as *mut u32 as _),
                size_of::<u32>() as u32,
                Some(&mut version as *mut u32 as _),
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

    /// Initializes the fast i/o and submits the initial shared memory section into the NDIS filter driver
    pub fn initialize_fast_io<const N: usize>(
        &self,
        fast_io_section: &mut FastIoSection<N>,
    ) -> Result<()> {
        let params = InitializeFastIoParams::<N> {
            header_ptr: fast_io_section as *mut FastIoSection<N>,
            data_size: N as u32,
        };

        let result = unsafe {
            DeviceIoControl(
                self.driver_handle,
                IOCTL_NDISRD_INITIALIZE_FAST_IO,
                Some(&params as *const InitializeFastIoParams<N> as *const std::ffi::c_void),
                size_of::<InitializeFastIoParams<N>>() as u32,
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

    /// This function is used to perform a query operation on the adapter pointed by oid_request.adapter_handle.
    /// With this function, it is possible to obtain various parameters of the network adapter, like the dimension
    /// of the internal buffers, the link speed or the counter of corrupted packets. The constants that define the
    /// operations are declared in the file ntddndis.h.
    pub fn ndis_get_request<T>(&self, oid_request: &mut PacketOidData<T>) -> Result<()> {
        let result = unsafe {
            DeviceIoControl(
                self.driver_handle,
                IOCTL_NDISRD_NDIS_GET_REQUEST,
                Some(oid_request as *const PacketOidData<T> as *const std::ffi::c_void),
                size_of::<PacketOidData<T>>() as u32,
                Some(oid_request as *const PacketOidData<T> as *mut std::ffi::c_void),
                size_of::<PacketOidData<T>>() as u32,
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

    /// This function is used to perform a set operation on the adapter pointed by oid_request.adapter_handle.
    /// With this function, it is possible to set various parameters of the network adapter, like the dimension
    /// of the internal buffers, the link speed or the counter of corrupted packets. The constants that define the
    /// operations are declared in the file ntddndis.h.
    pub fn ndis_set_request<T>(&self, oid_request: &PacketOidData<T>) -> Result<()> {
        let result = unsafe {
            DeviceIoControl(
                self.driver_handle,
                IOCTL_NDISRD_NDIS_SET_REQUEST,
                Some(oid_request as *const PacketOidData<T> as *const std::ffi::c_void),
                size_of::<PacketOidData<T>>() as u32,
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

    /// Initializes new Ndisapi instance opening the NDIS filter driver
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

    /// Reads the the single packet (IntermediateBuffer) from the driver
    ///
    /// # Safety
    ///
    /// This function is unsafe becasue EthRequest.packet may not be initilized or point to
    /// the invalid memory.
    pub unsafe fn read_packet(&self, packet: &mut EthRequest) -> Result<()> {
        let result = unsafe {
            DeviceIoControl(
                self.driver_handle,
                IOCTL_NDISRD_READ_PACKET,
                Some(packet as *const EthRequest as *const std::ffi::c_void),
                size_of::<EthRequest>() as u32,
                Some(packet as *mut EthRequest as *mut std::ffi::c_void),
                size_of::<EthRequest>() as u32,
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

    /// Reads the block of packets (IntermediateBuffer) from the driver
    ///
    /// # Safety
    ///
    /// This function is unsafe becasue EthMRequest<N>.packets may not be initilized or point to
    /// the invalid memory.
    pub unsafe fn read_packets<const N: usize>(
        &self,
        packets: &mut EthMRequest<N>,
    ) -> Result<usize> {
        let result = unsafe {
            DeviceIoControl(
                self.driver_handle,
                IOCTL_NDISRD_READ_PACKETS,
                Some(packets as *const EthMRequest<N> as *const std::ffi::c_void),
                size_of::<EthMRequest<N>>() as u32,
                Some(packets as *mut EthMRequest<N> as *mut std::ffi::c_void),
                size_of::<EthMRequest<N>>() as u32,
                None,
                None,
            )
        };

        if result.as_bool() {
            Ok(packets.packet_success as usize)
        } else {
            Err(unsafe { GetLastError() }.into())
        }
    }

    /// Reads the bunch of queued packets from the device NDIS filter driver (regardless of the network interface)
    pub fn read_packets_unsorted<const N: usize>(
        &self,
        packets: &mut [IntermediateBuffer; N],
    ) -> Result<usize> {
        let mut request = UnsortedReadSendRequest::<N> {
            packets: packets as *mut [IntermediateBuffer; N],
            packets_num: N as u32,
        };

        let result = unsafe {
            DeviceIoControl(
                self.driver_handle,
                IOCTL_NDISRD_READ_PACKETS_UNSORTED,
                Some(&request as *const UnsortedReadSendRequest<N> as *const std::ffi::c_void),
                size_of::<UnsortedReadSendRequest<N>>() as u32,
                Some(&mut request as *mut UnsortedReadSendRequest<N> as *mut std::ffi::c_void),
                size_of::<UnsortedReadSendRequest<N>>() as u32,
                None,
                None,
            )
        };

        if !result.as_bool() {
            Err(unsafe { GetLastError() }.into())
        } else {
            Ok(request.packets_num as usize)
        }
    }

    /// Removes static filter table from the NDIS filter driver
    pub fn reset_packet_filter_table(&self) -> Result<()> {
        let result = unsafe {
            DeviceIoControl(
                self.driver_handle,
                IOCTL_NDISRD_RESET_PACKET_FILTERS,
                None,
                0,
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

    /// Writes the single packet (IntermediateBuffer) to the driver to be indicated downwards the network stack
    ///
    /// # Safety
    ///
    /// This function is unsafe becasue EthRequest.packet may not be initilized or point to
    /// the invalid memory.
    pub unsafe fn send_packet_to_adapter(&self, packet: &EthRequest) -> Result<()> {
        let result = unsafe {
            DeviceIoControl(
                self.driver_handle,
                IOCTL_NDISRD_SEND_PACKET_TO_ADAPTER,
                Some(packet as *const EthRequest as *const std::ffi::c_void),
                size_of::<EthRequest>() as u32,
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

    /// Writes the single packet (IntermediateBuffer) to the driver to be indicated downwards the network stack
    ///
    /// # Safety
    ///
    /// This function is unsafe becasue EthRequest.packet may not be initilized or point to
    /// the invalid memory.
    pub unsafe fn send_packet_to_mstcp(&self, packet: &EthRequest) -> Result<()> {
        let result = unsafe {
            DeviceIoControl(
                self.driver_handle,
                IOCTL_NDISRD_SEND_PACKET_TO_MSTCP,
                Some(packet as *const EthRequest as *const std::ffi::c_void),
                size_of::<EthRequest>() as u32,
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

    /// Writes the block of packets (IntermediateBuffer) to the driver to be indicated downwards the network stack
    ///
    /// # Safety
    ///
    /// This function is unsafe becasue EthMRequest<N>.packets may not be initilized or point to
    /// the invalid memory.
    pub unsafe fn send_packets_to_adapter<const N: usize>(
        &self,
        packets: &EthMRequest<N>,
    ) -> Result<()> {
        let result = unsafe {
            DeviceIoControl(
                self.driver_handle,
                IOCTL_NDISRD_SEND_PACKETS_TO_ADAPTER,
                Some(packets as *const EthMRequest<N> as *const std::ffi::c_void),
                size_of::<EthMRequest<N>>() as u32,
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

    /// Sends the bunch of packets to the device NDIS filter driver to forward to the network interface. Please note that target
    /// adapter handle should be set in the IntermediateBuffer.header.adapter_handle
    pub fn send_packets_to_adapters_unsorted<const N: usize>(
        &self,
        packets: &mut [IntermediateBuffer; N],
        packets_num: usize,
    ) -> Result<usize> {
        let mut request = UnsortedReadSendRequest::<N> {
            packets: packets as *mut [IntermediateBuffer; N],
            packets_num: packets_num as u32,
        };

        let result = unsafe {
            DeviceIoControl(
                self.driver_handle,
                IOCTL_NDISRD_SEND_PACKET_TO_ADAPTER_UNSORTED,
                Some(&request as *const UnsortedReadSendRequest<N> as *const std::ffi::c_void),
                size_of::<UnsortedReadSendRequest<N>>() as u32,
                Some(&mut request as *mut UnsortedReadSendRequest<N> as *mut std::ffi::c_void),
                size_of::<UnsortedReadSendRequest<N>>() as u32,
                None,
                None,
            )
        };

        if !result.as_bool() {
            Err(unsafe { GetLastError() }.into())
        } else {
            Ok(request.packets_num as usize)
        }
    }

    /// Writes the block of packets (IntermediateBuffer) to the driver to be indicated upwards the network stack
    ///
    /// # Safety
    ///
    /// This function is unsafe becasue EthMRequest<N>.packets may not be initilized or point to
    /// the invalid memory.
    pub unsafe fn send_packets_to_mstcp<const N: usize>(
        &self,
        packets: &EthMRequest<N>,
    ) -> Result<()> {
        let result = unsafe {
            DeviceIoControl(
                self.driver_handle,
                IOCTL_NDISRD_SEND_PACKETS_TO_MSTCP,
                Some(packets as *const EthMRequest<N> as *const std::ffi::c_void),
                size_of::<EthMRequest<N>>() as u32,
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

    /// Sends the bunch of packets to the device NDIS filter driver to forward to the protocols layer(mstcp). Please note that target
    /// adapter handle (to be indicated from) should be set in the IntermediateBuffer.header.adapter_handle
    pub fn send_packets_to_mstcp_unsorted<const N: usize>(
        &self,
        packets: &mut [IntermediateBuffer; N],
        packets_num: usize,
    ) -> Result<usize> {
        let mut request = UnsortedReadSendRequest::<N> {
            packets: packets as *mut [IntermediateBuffer; N],
            packets_num: packets_num as u32,
        };

        let result = unsafe {
            DeviceIoControl(
                self.driver_handle,
                IOCTL_NDISRD_SEND_PACKET_TO_MSTCP_UNSORTED,
                Some(&request as *const UnsortedReadSendRequest<N> as *const std::ffi::c_void),
                size_of::<UnsortedReadSendRequest<N>>() as u32,
                Some(&mut request as *mut UnsortedReadSendRequest<N> as *mut std::ffi::c_void),
                size_of::<UnsortedReadSendRequest<N>>() as u32,
                None,
                None,
            )
        };

        if !result.as_bool() {
            Err(unsafe { GetLastError() }.into())
        } else {
            Ok(request.packets_num as usize)
        }
    }

    /// The user application should create a Win32 event (with CreateEvent API call) and pass the event handle to this function.
    /// Helper driver will signal this event when TCP/IP bound adapter’s list changes (an example this happens on plug/unplug
    /// network card, disable/enable network connection or etc.).
    pub fn set_adapter_list_change_event(&self, event_handle: HANDLE) -> Result<()> {
        let result = unsafe {
            DeviceIoControl(
                self.driver_handle,
                IOCTL_NDISRD_SET_ADAPTER_EVENT,
                Some(&event_handle as *const HANDLE as *const std::ffi::c_void),
                size_of::<HANDLE>() as u32,
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

    /// Sets the packet filter mode for the selected network interface
    /// adapter_handle: must be set to the interface handle (obtained via call to get_tcpip_bound_adapters_info).
    /// flags: combination of the XXX_LISTEN or XXX_TUNNEL flags:
    /// MSTCP_FLAG_SENT_TUNNEL – queue all packets sent from MSTCP to network interface. Original packet dropped.
    /// MSTCP_FLAG_RECV_TUNNEL – queue all packets indicated by network interface to MSTCP. Original packet dropped.
    /// MSTCP_FLAG_SENT_LISTEN – queue all packets sent from MSTCP to network interface. Original packet goes ahead.
    /// MSTCP_FLAG_RECV_LISTEN – queue all packets indicated by network interface to MSTCP. Original packet goes ahead.
    /// MSTCP_FLAG_FILTER_DIRECT – In promiscuous mode TCP/IP stack receives all packets in the Ethernet segment and replies
    /// with various ICMP packets, to prevent this set this flag. All packets with destination MAC different from
    /// FF-FF-FF-FF-FF-FF and network interface current MAC will never reach MSTCP.
    pub fn set_adapter_mode(&self, adapter_handle: HANDLE, flags: FilterFlags) -> Result<()> {
        let adapter_mode = AdapterMode {
            adapter_handle,
            flags,
        };

        let result = unsafe {
            DeviceIoControl(
                self.driver_handle,
                IOCTL_NDISRD_SET_ADAPTER_MODE,
                Some(&adapter_mode as *const AdapterMode as *const std::ffi::c_void),
                size_of::<AdapterMode>() as u32,
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

    /// Sets current hardware packet filter (OID_GEN_CURRENT_PACKET_FILTER) for the specified network interface
    pub fn set_hw_packet_filter(&self, adapter_handle: HANDLE, filter: u32) -> Result<()> {
        let mut oid = PacketOidData::new(adapter_handle, OID_GEN_CURRENT_PACKET_FILTER, filter);

        self.ndis_set_request::<_>(&mut oid)?;

        Ok(())
    }

    /// The user application should create a Win32 event (with CreateEvent API call) and pass adapter handle and event handle
    /// to this function. The filter driver will signal this event when the hardware filter for the adapter changes.
    pub fn set_hw_packet_filter_event(&self, event_handle: HANDLE) -> Result<()> {
        let result = unsafe {
            DeviceIoControl(
                self.driver_handle,
                IOCTL_NDISRD_SET_ADAPTER_HWFILTER_EVENT,
                Some(&event_handle as *const HANDLE as *const std::ffi::c_void),
                size_of::<HANDLE>() as u32,
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

    /// Associates the specified Win32 event with specified network interface.
    /// This even will be signalled by the NDIS filter when it has queued packets available for read.
    pub fn set_packet_event(&self, adapter_handle: HANDLE, event_handle: HANDLE) -> Result<()> {
        let adapter_event = AdapterEvent {
            adapter_handle,
            event_handle,
        };

        let result = unsafe {
            DeviceIoControl(
                self.driver_handle,
                IOCTL_NDISRD_SET_EVENT,
                Some(&adapter_event as *const AdapterEvent as *const std::ffi::c_void),
                size_of::<AdapterEvent>() as u32,
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

    /// Loads static filter table into the NDIS filter driver
    pub fn set_packet_filter_table<const N: usize>(
        &self,
        filter_table: &StaticFilterTable<N>,
    ) -> Result<()> {
        let result = unsafe {
            DeviceIoControl(
                self.driver_handle,
                IOCTL_NDISRD_SET_PACKET_FILTERS,
                Some(filter_table as *const StaticFilterTable<N> as *const std::ffi::c_void),
                size_of::<StaticFilterTable<N>>() as u32,
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

    /// A user application should create a Win32 event (with CreateEvent API call) and pass the event handle to this function.
    /// The filter driver will signal this event when a WAN (dial-up, DSL, ADSL or etc.) connection is established or terminated.
    pub fn set_wan_event(&self, event_handle: HANDLE) -> Result<()> {
        let result = unsafe {
            DeviceIoControl(
                self.driver_handle,
                IOCTL_NDISRD_SET_WAN_EVENT,
                Some(&event_handle as *const HANDLE as *const std::ffi::c_void),
                size_of::<HANDLE>() as u32,
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
