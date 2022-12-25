pub mod driver{
    use std::mem::MaybeUninit;

    use windows::{
        core::*, Win32::Foundation::*,
    };

    pub const NDISRD_DRIVER_NAME: ::windows::core::PCWSTR = w!("\\\\.\\NDISRD");
    pub const ADAPTER_NAME_SIZE: u32 = 256;
    pub const ADAPTER_LIST_SIZE: u32 = 32;
    pub const ETHER_ADDR_LENGTH: u32 = 6;
    pub const MAX_ETHER_FRAME: u32 = 1514;
    pub const MSTCP_FLAG_SENT_TUNNEL: u32 = 1;
    pub const MSTCP_FLAG_RECV_TUNNEL: u32 = 2;
    pub const MSTCP_FLAG_SENT_LISTEN: u32 = 4;
    pub const MSTCP_FLAG_RECV_LISTEN: u32 = 8;
    pub const MSTCP_FLAG_FILTER_DIRECT: u32 = 16;
    pub const MSTCP_FLAG_LOOPBACK_FILTER: u32 = 32;
    pub const MSTCP_FLAG_LOOPBACK_BLOCK: u32 = 64;
    pub const PACKET_FLAG_ON_SEND: u32 = 1;
    pub const PACKET_FLAG_ON_RECEIVE: u32 = 2;
    pub const ANY_SIZE: u32 = 1;
    pub const RAS_LINK_BUFFER_LENGTH: u32 = 2048;
    pub const RAS_LINKS_MAX: u32 = 256;
    pub const ETH_802_3_SRC_ADDRESS: u32 = 1;
    pub const ETH_802_3_DEST_ADDRESS: u32 = 2;
    pub const ETH_802_3_PROTOCOL: u32 = 4;
    pub const IP_SUBNET_V4_TYPE: u32 = 1;
    pub const IP_RANGE_V4_TYPE: u32 = 2;
    pub const IP_V4_FILTER_SRC_ADDRESS: u32 = 1;
    pub const IP_V4_FILTER_DEST_ADDRESS: u32 = 2;
    pub const IP_V4_FILTER_PROTOCOL: u32 = 4;
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

    /** TcpAdapterList
     * * Rust equivalent for TCP_AdapterList
    */
    #[repr(C, packed)]
    #[derive(Debug, Copy, Clone)]
    pub struct TcpAdapterList {
        pub adapter_count: ::std::os::raw::c_ulong,
        pub adapter_name_list: [[::std::os::raw::c_uchar; 256usize]; 32usize],
        pub adapter_handle: [HANDLE; 32usize],
        pub adapter_medium_list: [::std::os::raw::c_uint; 32usize],
        pub current_address: [[::std::os::raw::c_uchar; 6usize]; 32usize],
        pub mtu: [::std::os::raw::c_ushort; 32usize],
    }

    /** ListEntry
     * * Rust equivalent for LIST_ENTRY
    */
    #[repr(C)]
    #[derive(Debug, Copy, Clone)]
    pub struct ListEntry {
        pub flink: *mut ListEntry,
        pub blink: *mut ListEntry,
    }

    /** IntermediateBufferHeaderUnion
     * * Rust equivalent for HANDLE and LIST_ENTRY union used for INTERMEDIATE_BUFFER
    */
    #[repr(C, packed)]
    #[derive(Copy, Clone)]
    pub union IntermediateBufferHeaderUnion {
        pub adapter_handle: HANDLE,
        pub list_entry: ListEntry,
    }

    /** IntermediateBuffer
     * * Rust equivalent for INTERMEDIATE_BUFFER
    */
    #[repr(C, packed)]
    #[derive(Copy, Clone)]
    pub struct IntermediateBuffer {
        pub header: IntermediateBufferHeaderUnion,
        pub device_flags: u32,
        pub length: u32,
        pub flags: u32,
        pub vlan_8021q: u32,
        pub filter_id: u32,
        pub reserved: [u32; 4usize],
        pub buffer: [u8; 1514usize],
    }

    impl IntermediateBuffer {
        pub fn new() -> Self {
            unsafe{
                MaybeUninit::zeroed().assume_init()
            }
        }
    }

    impl Default for IntermediateBuffer {
        fn default() -> Self {
            Self::new()
        }
    }

    /** AdapterMode
     * * Rust equivalent for ADAPTER_MODE
    */
    #[repr(C, packed)]
    #[derive(Debug, Copy, Clone)]
    pub struct AdapterMode {
        pub adapter_handle: HANDLE,
        pub flags: u32,
    }
    
    /** EthPacket
     * * Rust equivalent for NDISRD_ETH_Packet
    */
    #[repr(C, packed)]
    #[derive(Debug, Copy, Clone)]
    pub struct EthPacket {
        pub buffer: *mut IntermediateBuffer,
    }
    
    /** EthRequest
     * * Rust equivalent for ETH_REQUEST
    */
    #[repr(C, packed)]
    #[derive(Debug, Copy, Clone)]
    pub struct EthRequest {
        pub adapter_handle: HANDLE,
        pub packet: EthPacket,
    }

    /** EthMRequest
     * * Rust equivalent for ETH_M_REQUEST using const generics
    */
    #[repr(C, packed)]
    #[derive(Debug, Copy, Clone)]
    pub struct EthMRequest<const N: usize> {
        pub adapter_handle: HANDLE,
        pub packet_number: ::std::os::raw::c_uint,
        pub packet_success: ::std::os::raw::c_uint,
        pub packets: [EthPacket; N],
    }
    
    /** AdapterEvent
     * * Rust equivalent for ADAPTER_EVENT
    */
    #[repr(C, packed)]
    #[derive(Debug, Copy, Clone)]
    pub struct AdapterEvent {
        pub adapter_handle: HANDLE,
        pub event_handle: HANDLE,
    }
    
    pub const IOCTL_NDISRD_GET_VERSION : u32 = 0x830020c0;
    pub const IOCTL_NDISRD_GET_TCPIP_INTERFACES : u32 = 0x830020c4;
    pub const IOCTL_NDISRD_SEND_PACKET_TO_ADAPTER : u32 = 0x830020c8;
    pub const IOCTL_NDISRD_SEND_PACKET_TO_MSTCP : u32 = 0x830020cc;
    pub const IOCTL_NDISRD_READ_PACKET : u32 = 0x830020d0;
    pub const IOCTL_NDISRD_SET_ADAPTER_MODE : u32 = 0x830020d4;
    pub const IOCTL_NDISRD_FLUSH_ADAPTER_QUEUE : u32 = 0x830020d8;
    pub const IOCTL_NDISRD_SET_EVENT : u32 = 0x830020dc;
    pub const IOCTL_NDISRD_NDIS_SET_REQUEST : u32 = 0x830020e0;
    pub const IOCTL_NDISRD_NDIS_GET_REQUEST : u32 = 0x830020e4;
    pub const IOCTL_NDISRD_SET_WAN_EVENT : u32 = 0x830020e8;
    pub const IOCTL_NDISRD_SET_ADAPTER_EVENT : u32 = 0x830020ec;
    pub const IOCTL_NDISRD_ADAPTER_QUEUE_SIZE : u32 = 0x830020f0;
    pub const IOCTL_NDISRD_GET_ADAPTER_MODE : u32 = 0x830020f4;
    pub const IOCTL_NDISRD_SET_PACKET_FILTERS : u32 = 0x830020f8;
    pub const IOCTL_NDISRD_RESET_PACKET_FILTERS : u32 = 0x830020fc;
    pub const IOCTL_NDISRD_GET_PACKET_FILTERS_TABLESIZE : u32 = 0x83002100;
    pub const IOCTL_NDISRD_GET_PACKET_FILTERS : u32 = 0x83002104;
    pub const IOCTL_NDISRD_GET_PACKET_FILTERS_RESET_STATS : u32 = 0x83002108;
    pub const IOCTL_NDISRD_GET_RAS_LINKS : u32 = 0x8300210c;
    pub const IOCTL_NDISRD_SEND_PACKETS_TO_ADAPTER : u32 = 0x83002110;
    pub const IOCTL_NDISRD_SEND_PACKETS_TO_MSTCP : u32 = 0x83002114;
    pub const IOCTL_NDISRD_READ_PACKETS : u32 = 0x83002118;
    pub const IOCTL_NDISRD_SET_ADAPTER_HWFILTER_EVENT : u32 = 0x8300211c;
    pub const IOCTL_NDISRD_INITIALIZE_FAST_IO : u32 = 0x83002120;
    pub const IOCTL_NDISRD_READ_PACKETS_UNSORTED : u32 = 0x83002124;
    pub const IOCTL_NDISRD_SEND_PACKET_TO_ADAPTER_UNSORTED : u32 = 0x83002128;
    pub const IOCTL_NDISRD_SEND_PACKET_TO_MSTCP_UNSORTED : u32 = 0x8300212c;
    pub const IOCTL_NDISRD_ADD_SECOND_FAST_IO_SECTION : u32 = 0x83002130;
}