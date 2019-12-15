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

use crate::{Error, Result};

/// Represents a UDP header and payload
#[derive(Debug, Copy, Clone)]
pub struct UdpPdu<'a> {
    buffer: &'a [u8],
}

/// Contains the inner payload of a [`UdpPdu`]
#[derive(Debug, Copy, Clone)]
pub enum Udp<'a> {
    Raw(&'a [u8]),
}

impl<'a> UdpPdu<'a> {
    /// Constructs a [`UdpPdu`] backed by the provided `buffer`
    pub fn new(buffer: &'a [u8]) -> Result<Self> {
        if buffer.len() < 8 {
            return Err(Error::Truncated);
        }
        Ok(UdpPdu { buffer })
    }

    /// Returns a reference to the entire underlying buffer that was provided during construction
    pub fn buffer(&'a self) -> &'a [u8] {
        self.buffer
    }

    /// Returns the slice of the underlying buffer that contains the header part of this PDU
    pub fn as_bytes(&'a self) -> &'a [u8] {
        &self.buffer[0..8]
    }

    /// Returns an object representing the inner payload of this PDU
    pub fn inner(&'a self) -> Result<Udp<'a>> {
        Ok(Udp::Raw(&self.buffer[8..]))
    }

    pub fn source_port(&'a self) -> u16 {
        u16::from_be_bytes([self.buffer[0], self.buffer[1]])
    }

    pub fn destination_port(&'a self) -> u16 {
        u16::from_be_bytes([self.buffer[2], self.buffer[3]])
    }

    pub fn length(&'a self) -> u16 {
        u16::from_be_bytes([self.buffer[4], self.buffer[5]])
    }

    pub fn checksum(&'a self) -> u16 {
        u16::from_be_bytes([self.buffer[6], self.buffer[7]])
    }
}