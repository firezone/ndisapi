use bitflags::bitflags;
use windows::{core::w, Win32::Foundation::HANDLE};

pub const NDISRD_DRIVER_NAME: ::windows::core::PCWSTR = w!("\\\\.\\NDISRD");
pub const ADAPTER_NAME_SIZE: usize = 256;
pub const ADAPTER_LIST_SIZE: usize = 32;
pub const ETHER_ADDR_LENGTH: usize = 6;
pub const MAX_ETHER_FRAME: usize = 1514; // 9014usize bytes if driver was built with the JUMBO_FRAME_SUPPORTED
pub const RAS_LINK_BUFFER_LENGTH: usize = 2048;
pub const RAS_LINKS_MAX: usize = 256;
pub const IP_SUBNET_V4_TYPE: u32 = 1;
pub const IP_RANGE_V4_TYPE: u32 = 2;
pub const IP_SUBNET_V6_TYPE: u32 = 1;
pub const IP_RANGE_V6_TYPE: u32 = 2;
pub const IP_V6_FILTER_SRC_ADDRESS: u32 = 1;
pub const IP_V6_FILTER_DEST_ADDRESS: u32 = 2;
pub const IP_V6_FILTER_PROTOCOL: u32 = 4;
pub const TCPUDP_SRC_PORT: u32 = 1;
pub const TCPUDP_DEST_PORT: u32 = 2;
pub const TCPUDP_TCP_FLAGS: u32 = 4;
pub const ICMP_TYPE: u32 = 1;
pub const ICMP_CODE: u32 = 2;
pub const ETH_802_3: u32 = 1;
pub const IPV4: u32 = 1;
pub const IPV6: u32 = 2;
pub const TCPUDP: u32 = 1;
pub const ICMP: u32 = 2;
pub const FILTER_PACKET_PASS: u32 = 1;
pub const FILTER_PACKET_DROP: u32 = 2;
pub const FILTER_PACKET_REDIRECT: u32 = 3;
pub const FILTER_PACKET_PASS_RDR: u32 = 4;
pub const FILTER_PACKET_DROP_RDR: u32 = 5;
pub const DATA_LINK_LAYER_VALID: u32 = 1;
pub const NETWORK_LAYER_VALID: u32 = 2;
pub const TRANSPORT_LAYER_VALID: u32 = 4;

bitflags! {
    #[derive(Default)]
    pub struct FilterFlags: u32 {
        const MSTCP_FLAG_SENT_TUNNEL = 1;
        const MSTCP_FLAG_RECV_TUNNEL = 2;
        const MSTCP_FLAG_SENT_LISTEN = 4;
        const MSTCP_FLAG_RECV_LISTEN = 8;
        const MSTCP_FLAG_FILTER_DIRECT = 16;
        const MSTCP_FLAG_LOOPBACK_FILTER = 32;
        const MSTCP_FLAG_LOOPBACK_BLOCK = 64;
        const MSTCP_FLAG_SENT_RECEIVE_TUNNEL = Self::MSTCP_FLAG_SENT_TUNNEL.bits | Self::MSTCP_FLAG_RECV_TUNNEL.bits;
        const MSTCP_FLAG_SENT_RECEIVE_LISTEN = Self::MSTCP_FLAG_SENT_LISTEN.bits | Self::MSTCP_FLAG_RECV_LISTEN.bits;
    }
}

bitflags! {
    #[derive(Default)]
    pub struct DirectionFlags: u32 {
        const PACKET_FLAG_ON_SEND = 1;
        const PACKET_FLAG_ON_RECEIVE = 2;
        const PACKET_FLAG_ON_SEND_RECEIVE = Self::PACKET_FLAG_ON_SEND.bits | Self::PACKET_FLAG_ON_RECEIVE.bits;
    }
}

bitflags! {
    #[derive(Default)]
    pub struct Eth802_3FilterFlags: u32 {
        const ETH_802_3_SRC_ADDRESS = 1;
        const ETH_802_3_DEST_ADDRESS = 2;
        const ETH_802_3_PROTOCOL = 4;
    }
}

bitflags! {
    #[derive(Default)]
    pub struct IpV4FilterFlags: u32 {
        const IP_V4_FILTER_SRC_ADDRESS = 1;
        const IP_V4_FILTER_DEST_ADDRESS = 2;
        const IP_V4_FILTER_PROTOCOL = 4;
    }
}

/// TcpAdapterList
/// * Rust equivalent for [_TCP_AdapterList](https://www.ntkernel.com/docs/windows-packet-filter-documentation/structures/_tcp_adapterlist/)
#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct TcpAdapterList {
    pub adapter_count: u32,
    pub adapter_name_list: [[u8; ADAPTER_NAME_SIZE]; ADAPTER_LIST_SIZE],
    pub adapter_handle: [HANDLE; ADAPTER_LIST_SIZE],
    pub adapter_medium_list: [u32; ADAPTER_LIST_SIZE],
    pub current_address: [[u8; ETHER_ADDR_LENGTH]; ADAPTER_LIST_SIZE],
    pub mtu: [u16; ADAPTER_LIST_SIZE],
}

/// ListEntry
/// * Rust equivalent for [_LIST_ENTRY](https://learn.microsoft.com/en-us/windows/win32/api/ntdef/ns-ntdef-list_entry)
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct ListEntry {
    pub flink: *mut ListEntry,
    pub blink: *mut ListEntry,
}

/// IntermediateBufferHeaderUnion
/// * Rust equivalent for HANDLE and LIST_ENTRY union used for INTERMEDIATE_BUFFER
#[repr(C, packed)]
#[derive(Copy, Clone)]
pub union IntermediateBufferHeaderUnion {
    pub adapter_handle: HANDLE,
    pub list_entry: ListEntry,
}

impl Default for IntermediateBufferHeaderUnion {
    fn default() -> Self {
        // SAFETY: This union contains either a `HANDLE` or a `ListEntry`
        // ListEntry: is an union of raw pointers which can be safely zeroed(as long as you not dereference it)
        // HANDLE: is just an `isize` wrapper which can also be zeroed
        unsafe { core::mem::zeroed() }
    }
}

/// IntermediateBuffer
/// * Rust equivalent for [_INTERMEDIATE_BUFFER](https://www.ntkernel.com/docs/windows-packet-filter-documentation/structures/_intermediate_buffer/)
#[repr(C, packed)]
#[derive(Copy, Clone, Default)]
pub struct IntermediateBuffer {
    pub header: IntermediateBufferHeaderUnion,
    pub device_flags: DirectionFlags,
    pub length: u32,
    pub flags: u32,
    pub vlan_8021q: u32,
    pub filter_id: u32,
    pub reserved: [u32; 4usize],
    pub buffer: Buffer,
}

#[repr(transparent)]
#[derive(Copy, Clone)]
pub struct Buffer(pub [u8; MAX_ETHER_FRAME]);

impl Default for Buffer {
    fn default() -> Self {
        Self([0; MAX_ETHER_FRAME])
    }
}

impl IntermediateBuffer {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn get_device_flags(&self) -> DirectionFlags {
        self.device_flags
    }
}

/// AdapterMode
/// * Rust equivalent for [_ADAPTER_MODE](https://www.ntkernel.com/docs/windows-packet-filter-documentation/structures/adapter_mode/)
#[repr(C, packed)]
#[derive(Debug, Copy, Clone, Default)]
pub struct AdapterMode {
    pub adapter_handle: HANDLE,
    pub flags: FilterFlags,
}

/// EthPacket
/// * Rust equivalent for [_NDISRD_ETH_Packet](https://www.ntkernel.com/docs/windows-packet-filter-documentation/structures/_ndisrd_eth_packet/)
#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct EthPacket {
    pub buffer: *mut IntermediateBuffer,
}

impl EthPacket {
    /// Returns the mutable reference to the IntermediateBuffer pointed to by the EthPacket
    ///
    /// # Safety
    ///
    /// This function is unsafe becasue EthPacket.buffer may not be initilized or point to
    /// the invalid memory.
    pub unsafe fn get_buffer_mut(&mut self) -> &mut IntermediateBuffer {
        &mut *self.buffer
    }

    /// Returns the reference to the IntermediateBuffer pointed to by the EthPacket
    ///
    /// # Safety
    ///
    /// This function is unsafe because EthPacket.buffer may not be initilized or point to
    /// the invalid memory.
    pub unsafe fn get_buffer(&self) -> &IntermediateBuffer {
        &mut *self.buffer
    }
}

/// EthRequest
/// * Rust equivalent for [_ETH_REQUEST](https://www.ntkernel.com/docs/windows-packet-filter-documentation/structures/_eth_request/)
#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct EthRequest {
    pub adapter_handle: HANDLE,
    pub packet: EthPacket,
}

/// EthMRequest
/// * Rust equivalent for [_ETH_M_REQUEST](https://www.ntkernel.com/docs/windows-packet-filter-documentation/structures/_eth_m_request/)
#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct EthMRequest<const N: usize> {
    pub adapter_handle: HANDLE,
    pub packet_number: ::std::os::raw::c_uint,
    pub packet_success: ::std::os::raw::c_uint,
    pub packets: [EthPacket; N],
}

impl<const N: usize> EthMRequest<N> {
    pub fn new(adapter_handle: HANDLE) -> Self {
        Self {
            adapter_handle,
            packet_number: 0,
            packet_success: 0,
            packets: [EthPacket {
                buffer: core::ptr::null_mut(),
            }; N],
        }
    }
}

/// AdapterEvent
/// * Rust equivalent for [_ADAPTER_EVENT](https://www.ntkernel.com/docs/windows-packet-filter-documentation/structures/adapter_event/)
#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct AdapterEvent {
    pub adapter_handle: HANDLE,
    pub event_handle: HANDLE,
}

/// PacketOidData
/// * Rust equivalent for [_PACKET_OID_DATA](https://www.ntkernel.com/docs/windows-packet-filter-documentation/structures/_packet_oid_data/)
#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct PacketOidData<const N: usize> {
    pub adapter_handle: HANDLE,
    pub oid: u32,
    pub length: u32,
    pub data: [u8; N],
}

impl<const N: usize> PacketOidData<N> {
    pub fn new(adapter_handle: HANDLE, oid: u32) -> Self {
        Self {
            adapter_handle,
            oid,
            length: N as u32,
            data: [0u8; N],
        }
    }
}

/// RasLinkInformation
/// * Rust equivalent for [_RAS_LINK_INFO](https://www.ntkernel.com/docs/windows-packet-filter-documentation/structures/_ras_link_info/)
#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct RasLinkInformation {
    link_speed: u32,
    maximum_total_size: u32,
    remote_address: [u8; ETHER_ADDR_LENGTH],
    local_address: [u8; ETHER_ADDR_LENGTH],
    protocol_buffer_length: u32,
    protocol_buffer: [u8; RAS_LINK_BUFFER_LENGTH],
}

impl RasLinkInformation {
    pub fn get_link_speed(&self) -> u32 {
        self.link_speed
    }

    pub fn get_maximum_total_size(&self) -> u32 {
        self.maximum_total_size
    }

    pub fn get_remote_address(&self) -> &[u8; ETHER_ADDR_LENGTH] {
        &self.remote_address
    }

    pub fn get_local_address(&self) -> &[u8; ETHER_ADDR_LENGTH] {
        &self.local_address
    }

    pub fn get_protocol_buffer_length(&self) -> usize {
        self.protocol_buffer_length as usize
    }

    pub fn get_protocol_buffer(&self) -> &[u8; RAS_LINK_BUFFER_LENGTH] {
        &self.protocol_buffer
    }
}

/// RasLinks
/// * Rust equivalent for [_RAS_LINKS](https://www.ntkernel.com/docs/windows-packet-filter-documentation/structures/_ras_links/)
#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct RasLinks {
    pub number_of_links: u32,
    pub ras_links: [RasLinkInformation; RAS_LINKS_MAX],
}

impl Default for RasLinks {
    fn default() -> Self {
        // SAFETY: This structure is filled by the information by NDIS filter driver when passed as a memory buffer
        // along with IOCTL_NDISRD_GET_RAS_LINKS. It is safe to be zeroed because contains only values and arrays that
        // can be default initialized with zeroes
        unsafe { std::mem::zeroed() }
    }
}

/// Eth802_3Filter
/// * Rust equivalent for [_ETH_802_3_FILTER](https://www.ntkernel.com/docs/windows-packet-filter-documentation/structures/_eth_802_3_filter/)
#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct Eth802_3Filter {
    pub valid_fields: Eth802_3FilterFlags,
    pub src_address: [u8; ETHER_ADDR_LENGTH],
    pub dest_address: [u8; ETHER_ADDR_LENGTH],
    pub protocol: u16,
    pub padding: u16,
}

impl Default for Eth802_3Filter {
    fn default() -> Self {
        // SAFETY: It is safe to be zeroed because contains only values and arrays that
        // can be default initialized with zeroes
        unsafe { std::mem::zeroed() }
    }
}

/// IpSubnetV4
/// * Rust equivalent for [_IP_SUBNET_V4](https://www.ntkernel.com/docs/windows-packet-filter-documentation/structures/_ip_subnet_v4/)
#[repr(C, packed)]
#[derive(Default, Debug, Copy, Clone)]
pub struct IpSubnetV4 {
    pub ip: u32,
    pub ip_mask: u32,
}

/// IpRangeV4
/// * Rust equivalent for [_IP_RANGE_V4](https://www.ntkernel.com/docs/windows-packet-filter-documentation/structures/_ip_range_v4/)
#[repr(C, packed)]
#[derive(Default, Debug, Copy, Clone)]
pub struct IpRangeV4 {
    pub start_ip: u32,
    pub end_ip: u32,
}

#[repr(C, packed)]
#[derive(Copy, Clone)]
pub union IpAddressV4Union {
    pub ip_subnet: IpSubnetV4,
    pub ip_range: IpRangeV4,
}

impl Default for IpAddressV4Union {
    fn default() -> Self {
        // SAFETY: This union contains either a `IpSubnetV4` or a `IpRangeV4`
        // IpSubnetV4: when zeroed is equivalent to 0.0.0.0/0
        // IpRangeV4: when zeroed is equivalent to 0.0.0.0 - 0.0.0.0
        unsafe { std::mem::zeroed() }
    }
}

/// IpAddressV4
/// * Rust equivalent for [_IP_ADDRESS_V4](https://www.ntkernel.com/docs/windows-packet-filter-documentation/structures/_ip_address_v4/)
#[repr(C, packed)]
#[derive(Default, Copy, Clone)]
pub struct IpAddressV4 {
    pub address_type: u32, // IP_SUBNET_V4_TYPE or IP_RANGE_V4_TYPE
    pub address: IpAddressV4Union,
}

/// IpV4Filter
/// * Rust equivalent for [_IP_V4_FILTER](https://www.ntkernel.com/docs/windows-packet-filter-documentation/structures/_ip_v4_filter/)
#[repr(C, packed)]
#[derive(Default, Copy, Clone)]
pub struct IpV4Filter {
    pub valid_fields: IpV4FilterFlags,
    pub src_address: IpAddressV4,
    pub dest_address: IpAddressV4,
    pub protocol: u8,
    pub padding: [u8; 3usize],
}

pub const IOCTL_NDISRD_GET_VERSION: u32 = 0x830020c0;
pub const IOCTL_NDISRD_GET_TCPIP_INTERFACES: u32 = 0x830020c4;
pub const IOCTL_NDISRD_SEND_PACKET_TO_ADAPTER: u32 = 0x830020c8;
pub const IOCTL_NDISRD_SEND_PACKET_TO_MSTCP: u32 = 0x830020cc;
pub const IOCTL_NDISRD_READ_PACKET: u32 = 0x830020d0;
pub const IOCTL_NDISRD_SET_ADAPTER_MODE: u32 = 0x830020d4;
pub const IOCTL_NDISRD_FLUSH_ADAPTER_QUEUE: u32 = 0x830020d8;
pub const IOCTL_NDISRD_SET_EVENT: u32 = 0x830020dc;
pub const IOCTL_NDISRD_NDIS_SET_REQUEST: u32 = 0x830020e0;
pub const IOCTL_NDISRD_NDIS_GET_REQUEST: u32 = 0x830020e4;
pub const IOCTL_NDISRD_SET_WAN_EVENT: u32 = 0x830020e8;
pub const IOCTL_NDISRD_SET_ADAPTER_EVENT: u32 = 0x830020ec;
pub const IOCTL_NDISRD_ADAPTER_QUEUE_SIZE: u32 = 0x830020f0;
pub const IOCTL_NDISRD_GET_ADAPTER_MODE: u32 = 0x830020f4;
pub const IOCTL_NDISRD_SET_PACKET_FILTERS: u32 = 0x830020f8;
pub const IOCTL_NDISRD_RESET_PACKET_FILTERS: u32 = 0x830020fc;
pub const IOCTL_NDISRD_GET_PACKET_FILTERS_TABLESIZE: u32 = 0x83002100;
pub const IOCTL_NDISRD_GET_PACKET_FILTERS: u32 = 0x83002104;
pub const IOCTL_NDISRD_GET_PACKET_FILTERS_RESET_STATS: u32 = 0x83002108;
pub const IOCTL_NDISRD_GET_RAS_LINKS: u32 = 0x8300210c;
pub const IOCTL_NDISRD_SEND_PACKETS_TO_ADAPTER: u32 = 0x83002110;
pub const IOCTL_NDISRD_SEND_PACKETS_TO_MSTCP: u32 = 0x83002114;
pub const IOCTL_NDISRD_READ_PACKETS: u32 = 0x83002118;
pub const IOCTL_NDISRD_SET_ADAPTER_HWFILTER_EVENT: u32 = 0x8300211c;
pub const IOCTL_NDISRD_INITIALIZE_FAST_IO: u32 = 0x83002120;
pub const IOCTL_NDISRD_READ_PACKETS_UNSORTED: u32 = 0x83002124;
pub const IOCTL_NDISRD_SEND_PACKET_TO_ADAPTER_UNSORTED: u32 = 0x83002128;
pub const IOCTL_NDISRD_SEND_PACKET_TO_MSTCP_UNSORTED: u32 = 0x8300212c;
pub const IOCTL_NDISRD_ADD_SECOND_FAST_IO_SECTION: u32 = 0x83002130;
