// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Implements readers and writers that compute the CRC64 checksum of the bytes
//! read/written.

use crc64::crc64;
use std::io::{Read, Write};

/// Computes the CRC64 checksum of the read bytes.
///
/// ```
/// use std::io::Read;
/// use versionize::crc::CRC64Reader;
///
/// let buf = vec![1, 2, 3, 4, 5];
/// let mut read_buf = Vec::new();
/// let mut slice = buf.as_slice();
///
/// // Create a reader from a slice.
/// let mut crc_reader = CRC64Reader::new(&mut slice);
///
/// let count = crc_reader.read_to_end(&mut read_buf).unwrap();
/// assert_eq!(crc_reader.checksum(), 0xFB04_60DE_0638_3654);
/// assert_eq!(read_buf, buf);
/// ```
pub struct CRC64Reader<T> {
    reader: T,
    crc64: u64,
}

impl<T> CRC64Reader<T>
where
    T: Read,
{
    /// Create a new reader.
    pub fn new(reader: T) -> Self {
        CRC64Reader { crc64: 0, reader }
    }
    /// Returns the current checksum value.
    pub fn checksum(&self) -> u64 {
        self.crc64
    }
}

impl<T> Read for CRC64Reader<T>
where
    T: Read,
{
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let bytes_read = self.reader.read(buf)?;
        self.crc64 = crc64(self.crc64, &buf[..bytes_read]);
        Ok(bytes_read)
    }
}

/// Computes the CRC64 checksum of the written bytes.
///
/// ```
/// use std::io::Write;
/// use versionize::crc::CRC64Writer;
///
/// let mut buf = vec![0; 16];
/// let write_buf = vec![123; 16];
/// let mut slice = buf.as_mut_slice();
///
/// // Create a new writer from slice.
/// let mut crc_writer = CRC64Writer::new(&mut slice);
///
/// crc_writer.write_all(&write_buf.as_slice()).unwrap();
/// assert_eq!(crc_writer.checksum(), 0x29D5_3572_1632_6566);
/// assert_eq!(write_buf, buf);
/// ```
pub struct CRC64Writer<T> {
    writer: T,
    crc64: u64,
}

impl<T> CRC64Writer<T>
where
    T: Write,
{
    /// Create a new writer.
    pub fn new(writer: T) -> Self {
        CRC64Writer { crc64: 0, writer }
    }

    /// Returns the current checksum value.
    pub fn checksum(&self) -> u64 {
        self.crc64
    }
}

impl<T> Write for CRC64Writer<T>
where
    T: Write,
{
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let bytes_written = self.writer.write(buf)?;
        self.crc64 = crc64(self.crc64, &buf[..bytes_written]);
        Ok(bytes_written)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.writer.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::{CRC64Reader, CRC64Writer, Read, Write};

    #[test]
    fn test_crc_new() {
        let buf = vec![1; 5];
        let mut slice = buf.as_slice();
        let crc_reader = CRC64Reader::new(&mut slice);
        assert_eq!(crc_reader.crc64, 0);
        assert_eq!(crc_reader.reader, &[1; 5]);
        assert_eq!(crc_reader.checksum(), 0);

        let mut buf = vec![0; 5];
        let mut slice = buf.as_mut_slice();
        let crc_writer = CRC64Writer::new(&mut slice);
        assert_eq!(crc_writer.crc64, 0);
        assert_eq!(crc_writer.writer, &[0; 5]);
        assert_eq!(crc_writer.checksum(), 0);
    }

    #[test]
    fn test_crc_read() {
        let buf = vec![1, 2, 3, 4, 5];
        let mut read_buf = vec![0; 16];

        let mut slice = buf.as_slice();
        let mut crc_reader = CRC64Reader::new(&mut slice);
        crc_reader.read_to_end(&mut read_buf).unwrap();
        assert_eq!(crc_reader.checksum(), 0xFB04_60DE_0638_3654);
        assert_eq!(crc_reader.checksum(), crc_reader.crc64);
    }

    #[test]
    fn test_crc_write() {
        let mut buf = vec![0; 16];
        let write_buf = vec![123; 16];

        let mut slice = buf.as_mut_slice();
        let mut crc_writer = CRC64Writer::new(&mut slice);
        crc_writer.write_all(write_buf.as_slice()).unwrap();
        crc_writer.flush().unwrap();
        assert_eq!(crc_writer.checksum(), 0x29D5_3572_1632_6566);
        assert_eq!(crc_writer.checksum(), crc_writer.crc64);
    }
}
