use windows::{
    core::{Result, PCWSTR, PWSTR},
    s, w,
    Win32::System::Registry::{
        RegCloseKey, RegEnumKeyExW, RegOpenKeyExW, RegQueryValueExA, RegQueryValueExW, HKEY,
        HKEY_LOCAL_MACHINE, KEY_READ, REG_VALUE_TYPE,
    },
};

use std::str;

use super::Ndisapi;

const REGSTR_NETWORK_CONTROL_CLASS: ::windows::core::PCWSTR =
    w!("SYSTEM\\CurrentControlSet\\Control\\Class\\{4D36E972-E325-11CE-BFC1-08002BE10318}");
const REGSTR_VAL_NAME: ::windows::core::PCWSTR = w!("Name");
const REGSTR_COMPONENTID: ::windows::core::PCSTR = s!("ComponentId");
const REGSTR_LINKAGE: ::windows::core::PCWSTR = w!("Linkage");
const REGSTR_EXPORT: ::windows::core::PCSTR = s!("Export");
const REGSTR_COMPONENTID_NDISWANIP: &str = "ms_ndiswanip";
const REGSTR_COMPONENTID_NDISWANIPV6: &str = "ms_ndiswanipv6";
const REGSTR_COMPONENTID_NDISWANBH: &str = "ms_ndiswanbh";
const USER_NDISWANIP: &str = "WAN Network Interface (IP)";
const USER_NDISWANBH: &str = "WAN Network Interface (BH)";
const USER_NDISWANIPV6: &str = "WAN Network Interface (IPv6)";

impl Ndisapi {
    /// Enumerate all subkeys of HKLM\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}
    /// and look for the componentid = ms_ndiswanip, and then grab the linkage subkey and the export string it seems to work for
    /// at least both windows 7 and windows 10.
    /// Possible component id values:
    /// ms_ndiswanip
    /// ms_ndiswanipv6
    /// ms_ndiswanbh
    fn is_ndiswan_interface(adapter_name: impl Into<String>, component_id: &str) -> Result<bool> {
        let adapter_name = adapter_name.into();
        // Handles to registry keys
        let mut target_key = HKEY::default();
        let mut connection_key = HKEY::default();
        let mut linkage_key = HKEY::default();

        let result = unsafe {
            RegOpenKeyExW(
                HKEY_LOCAL_MACHINE,
                REGSTR_NETWORK_CONTROL_CLASS,
                0,
                KEY_READ,
                &mut target_key,
            )
        };

        if result.is_err() {
            return Err(result.into());
        }

        // Counter for enumerating registry keys
        let mut index = 0u32;

        // Buffers for storing registry values
        let mut buffer = vec![0u16; 256];
        let mut buffer_size = buffer.len() as u32;
        let mut temp_buffer = vec![0u8; 256];
        let mut temp_buffer_size = temp_buffer.len() as u32;

        // Set to true if found
        let mut found = false;

        while !found {
            let result = unsafe {
                RegEnumKeyExW(
                    target_key,
                    index,
                    PWSTR::from_raw(buffer.as_mut_ptr()),
                    &mut buffer_size as *mut u32,
                    None,
                    PWSTR::null(),
                    None,
                    None,
                )
            };

            if !result.is_ok() {
                break;
            } else {
                let result = unsafe {
                    RegOpenKeyExW(
                        target_key,
                        PCWSTR::from_raw(buffer.as_ptr()),
                        0,
                        KEY_READ,
                        &mut connection_key,
                    )
                };

                if result.is_ok() {
                    let mut value_type = REG_VALUE_TYPE::default();
                    let result = unsafe {
                        RegQueryValueExA(
                            connection_key,
                            REGSTR_COMPONENTID,
                            None,
                            Some(&mut value_type),
                            Some(temp_buffer.as_mut_ptr()),
                            Some(&mut temp_buffer_size),
                        )
                    };

                    if result.is_ok() {
                        let comp_id = if let Ok(id) =
                            str::from_utf8(&temp_buffer[..temp_buffer_size as usize])
                        {
                            id.trim_end_matches(char::from(0)).to_string()
                        } else {
                            String::default()
                        };

                        if comp_id.as_str() == component_id {
                            temp_buffer_size = temp_buffer.len() as u32;
                            let result = unsafe {
                                RegOpenKeyExW(
                                    connection_key,
                                    REGSTR_LINKAGE,
                                    0,
                                    KEY_READ,
                                    &mut linkage_key,
                                )
                            };

                            if result.is_ok() {
                                let result = unsafe {
                                    RegQueryValueExA(
                                        linkage_key,
                                        REGSTR_EXPORT,
                                        None,
                                        Some(&mut value_type),
                                        Some(temp_buffer.as_mut_ptr()),
                                        Some(&mut temp_buffer_size),
                                    )
                                };

                                if result.is_ok() {
                                    let export = if let Ok(id) =
                                        str::from_utf8(&temp_buffer[..temp_buffer_size as usize])
                                    {
                                        id.trim_end_matches(char::from(0)).to_string()
                                    } else {
                                        String::default()
                                    };

                                    if export.as_str().eq_ignore_ascii_case(adapter_name.as_str()) {
                                        found = true;
                                    }
                                }
                                unsafe {
                                    RegCloseKey(linkage_key);
                                }
                            }
                        }
                        unsafe {
                            RegCloseKey(connection_key);
                        }
                    }
                    temp_buffer_size = temp_buffer.len() as u32;
                }

                index += 1;
                buffer_size = buffer.len() as u32;
            }
        }

        unsafe {
            RegCloseKey(target_key);
        }

        Ok(found)
    }

    pub fn is_ndiswan_ip(adapter_name: impl Into<String>) -> bool {
        Self::is_ndiswan_interface(adapter_name.into(), REGSTR_COMPONENTID_NDISWANIP)
            .unwrap_or(false)
    }

    pub fn is_ndiswan_ipv6(adapter_name: impl Into<String>) -> bool {
        Self::is_ndiswan_interface(adapter_name.into(), REGSTR_COMPONENTID_NDISWANIPV6)
            .unwrap_or(false)
    }

    pub fn is_ndiswan_bh(adapter_name: impl Into<String>) -> bool {
        Self::is_ndiswan_interface(adapter_name.into(), REGSTR_COMPONENTID_NDISWANBH)
            .unwrap_or(false)
    }

    /// Obtains the user-friendly name of the network interface by system level name received from the network filter driver
    pub fn get_friendly_adapter_name(adapter_name: impl Into<String>) -> Result<String> {
        let mut adapter_name = adapter_name.into();

        if Self::is_ndiswan_ip(adapter_name.as_str()) {
            return Ok(USER_NDISWANIP.into());
        }

        if Self::is_ndiswan_ipv6(adapter_name.as_str()) {
            return Ok(USER_NDISWANIPV6.into());
        }

        if Self::is_ndiswan_bh(adapter_name.as_str()) {
            return Ok(USER_NDISWANBH.into());
        }

        // Trim the '\DEVICE\' prefix from the adapter system name
        adapter_name = adapter_name.replace("\\DEVICE\\", "");

        let friendly_name_key = format!(
            "SYSTEM\\CurrentControlSet\\Control\\Network\\{{4D36E972-E325-11CE-BFC1-08002BE10318}}\\{}\\Connection",
            &adapter_name
        );

        // Convert the string to UTF16 array and get a pointer to it as PCWSTR
        let mut friendly_name_key = friendly_name_key.encode_utf16().collect::<Vec<u16>>();
        friendly_name_key.push(0);
        let friendly_name_key_pwstr = PCWSTR::from_raw(friendly_name_key.as_ptr());

        let mut hkey = HKEY::default();

        let mut result = unsafe {
            RegOpenKeyExW(
                HKEY_LOCAL_MACHINE,
                friendly_name_key_pwstr,
                0,
                KEY_READ,
                &mut hkey,
            )
        };

        let mut value_type = REG_VALUE_TYPE::default();
        let mut data = vec![0u8; 512];
        let mut data_size = data.len() as u32;
        let mut friendly_name = String::default();

        if result.is_ok() {
            result = unsafe {
                RegQueryValueExW(
                    hkey,
                    REGSTR_VAL_NAME,
                    None,
                    Some(&mut value_type),
                    Some(data.as_mut_ptr()),
                    Some(&mut data_size),
                )
            };

            if result.is_ok() {
                friendly_name = if let Ok(name) = str::from_utf8(&data[..data_size as usize]) {
                    name.trim_end_matches(char::from(0)).to_string()
                } else {
                    String::default()
                }
            }

            unsafe {
                RegCloseKey(hkey);
            }
        }

        if !result.is_ok() {
            Err(result.into())
        } else {
            Ok(friendly_name)
        }
    }
}
