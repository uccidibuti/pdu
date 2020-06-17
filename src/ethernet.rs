/*
   Copyright (c) 2019 Alex Forster <alex@alexforster.com>

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.

   SPDX-License-Identifier: Apache-2.0
*/

use core::convert::TryInto;

use crate::{Error, Result};

/// Provides constants representing various EtherTypes supported by this crate
#[allow(non_snake_case)]
pub mod EtherType {
    pub const ARP: u16 = 0x0806;
    pub const IPV4: u16 = 0x0800;
    pub const IPV6: u16 = 0x86DD;
    pub const DOT1Q: u16 = 0x8100;
    pub const TEB: u16 = 0x6558;
}

/// Represents an Ethernet header and payload
#[derive(Debug, Copy, Clone)]
pub struct EthernetPdu<'a> {
    buffer: &'a [u8],
    #[cfg(feature = "bpf")]
    buffer_end_pointer: *const u8,
}

/// Contains the inner payload of an [`EthernetPdu`]
#[cfg(not(feature = "bpf"))]
#[derive(Debug, Copy, Clone)]
pub enum Ethernet<'a> {
    Raw(&'a [u8]),
    Arp(super::ArpPdu<'a>),
    Ipv4(super::Ipv4Pdu<'a>),
    Ipv6(super::Ipv6Pdu<'a>),
}

#[cfg(feature = "bpf")]
#[derive(Debug, Copy, Clone)]
pub enum Ethernet<'a> {
    Raw(&'a [u8]),
    // Arp(super::ArpPdu<'a>),
    Ipv4(super::Ipv4Pdu<'a>),
    // Ipv6(super::Ipv6Pdu<'a>),
}

impl<'a> EthernetPdu<'a> {
    /// Constructs an [`EthernetPdu`] backed by the provided `buffer`
    #[cfg(not(feature = "bpf"))]
    pub fn new(buffer: &'a [u8]) -> Result<Self> {
        if buffer.len() < 14 {
            return Err(Error::Truncated);
        }
        let pdu = EthernetPdu { buffer };
        if pdu.tpid() == EtherType::DOT1Q && buffer.len() < 18 {
            return Err(Error::Truncated);
        }
        if pdu.ethertype() < 0x0600 {
            // we don't support 802.3 (LLC) frames
            return Err(Error::Malformed);
        }
        Ok(pdu)
    }

    #[cfg_attr(feature = "bpf", inline(always))]
    #[cfg(feature = "bpf")]
    pub fn new(buffer: &'a [u8], buffer_end_pointer: *const u8) -> Result<Self> {
        if super::is_invalid_index(buffer, 30, buffer_end_pointer) {
            return Err(Error::Truncated);
        }
        let pdu = EthernetPdu { buffer, buffer_end_pointer };
        if pdu.tpid() == EtherType::DOT1Q && super::is_invalid_index(buffer, 18, buffer_end_pointer) {
            return Err(Error::Truncated);
        }
        if pdu.ethertype() < 0x0600 {
            // we don't support 802.3 (LLC) frames
            return Err(Error::Malformed);
        }
        Ok(pdu)
    }
    

    /// Returns a reference to the entire underlying buffer that was provided during construction
    #[cfg_attr(feature = "bpf", inline(always))]
    pub fn buffer(&'a self) -> &'a [u8] {
        self.buffer
    }

    /// Returns the slice of the underlying buffer that contains the header part of this PDU
    #[cfg_attr(feature = "bpf", inline(always))]
    pub fn as_bytes(&'a self) -> &'a [u8] {
        &self.buffer[0..self.computed_ihl()]
    }

    /// Returns an object representing the inner payload of this PDU
    #[cfg_attr(feature = "bpf", inline(always))]
    #[cfg(not(feature = "bpf"))]
    pub fn inner(&'a self) -> Result<Ethernet<'a>> {
        let rest = &self.buffer[self.computed_ihl()..];
        Ok(match self.ethertype() {
            EtherType::ARP => Ethernet::Arp(super::ArpPdu::new(rest)?),
            EtherType::IPV4 => Ethernet::Ipv4(super::Ipv4Pdu::new(rest)?),
            EtherType::IPV6 => Ethernet::Ipv6(super::Ipv6Pdu::new(rest)?),
            _ => Ethernet::Raw(rest),
        })
    }

    /// Returns an object representing the inner payload of this PDU
    #[cfg_attr(feature = "bpf", inline(always))]
    #[cfg(feature = "bpf")]
    pub fn inner(&'a self) -> Result<Ethernet<'a>> {
        let computed_ihl = self.computed_ihl();
        if super::is_invalid_index(self.buffer, computed_ihl as isize + 1, self.buffer_end_pointer) {
            return Err(Error::Truncated);
        }
        let rest = &self.buffer[computed_ihl..];
        Ok(match self.ethertype() {
            // EtherType::ARP => Ethernet::Arp(super::ArpPdu::new(rest)?),
            EtherType::IPV4 => Ethernet::Ipv4(super::Ipv4Pdu::new(rest, self.buffer_end_pointer)?),
            // EtherType::IPV6 => Ethernet::Ipv6(super::Ipv6Pdu::new(rest)?),
            _ => Ethernet::Raw(rest),
        })
    }

    #[cfg_attr(feature = "bpf", inline(always))]
    pub fn computed_ihl(&'a self) -> usize {
        match self.tpid() {
            EtherType::DOT1Q => 18,
            _ => 14,
        }
    }

    #[cfg_attr(feature = "bpf", inline(always))]
    pub fn source_address(&'a self) -> [u8; 6] {
        let mut source_address = [0u8; 6];
        source_address.copy_from_slice(&self.buffer[6..12]);
        source_address
    }

    #[cfg_attr(feature = "bpf", inline(always))]
    pub fn destination_address(&'a self) -> [u8; 6] {
        let mut destination_address = [0u8; 6];
        destination_address.copy_from_slice(&self.buffer[0..6]);
        destination_address
    }

    #[cfg_attr(feature = "bpf", inline(always))]
    pub fn tpid(&'a self) -> u16 {
        u16::from_be_bytes(self.buffer[12..=13].try_into().unwrap())
    }

    #[cfg_attr(feature = "bpf", inline(always))]
    pub fn ethertype(&'a self) -> u16 {
        match self.tpid() {
            EtherType::DOT1Q => u16::from_be_bytes(self.buffer[16..=17].try_into().unwrap()),
            ethertype => ethertype,
        }
    }

    #[cfg_attr(feature = "bpf", inline(always))]
    pub fn vlan(&'a self) -> Option<u16> {
        match self.tpid() {
            EtherType::DOT1Q => Some(u16::from_be_bytes(self.buffer[14..=15].try_into().unwrap()) & 0x0FFF),
            _ => None,
        }
    }

    #[cfg_attr(feature = "bpf", inline(always))]
    pub fn vlan_pcp(&'a self) -> Option<u8> {
        match self.tpid() {
            EtherType::DOT1Q => Some((self.buffer[14] & 0xE0) >> 5),
            _ => None,
        }
    }

    #[cfg_attr(feature = "bpf", inline(always))]
    pub fn vlan_dei(&'a self) -> Option<bool> {
        match self.tpid() {
            EtherType::DOT1Q => Some(((self.buffer[14] & 0x10) >> 4) > 0),
            _ => None,
        }
    }
}
