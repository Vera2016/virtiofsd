// Copyright © 2019 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause

#[macro_use]
extern crate log;

pub mod descriptor_utils;
pub mod file_traits;
pub mod filesystem;
pub mod fuse;
pub mod idmap;
pub mod limits;
pub mod macros;
pub mod oslib;
pub mod passthrough;
pub mod read_dir;
pub mod sandbox;
#[cfg(feature = "seccomp")]
pub mod seccomp;
pub mod server;
pub mod soft_idmap;
pub mod util;
pub mod vhost_user;

use std::ffi::{FromBytesWithNulError, FromVecWithNulError};
use std::{error, fmt, io};

#[derive(Debug)]
pub enum Error {
    /// Failed to decode protocol messages.
    DecodeMessage(io::Error),
    /// Failed to encode protocol messages.
    EncodeMessage(io::Error),
    /// Failed to flush protocol messages.
    FlushMessage(io::Error),
    /// One or more parameters are missing.
    MissingParameter,
    /// A C string parameter is invalid.
    InvalidCString(FromBytesWithNulError),
    /// A C string parameter is invalid.
    InvalidCString2(FromVecWithNulError),
    /// The `len` field of the header is too small.
    InvalidHeaderLength,
    /// The `size` field of the `SetxattrIn` message does not match the length
    /// of the decoded value.
    InvalidXattrSize((u32, usize)),
    /// One or more extensions are missing.
    MissingExtension,
}

impl error::Error for Error {}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use Error::*;
        match self {
            DecodeMessage(err) => write!(f, "failed to decode fuse message: {err}"),
            EncodeMessage(err) => write!(f, "failed to encode fuse message: {err}"),
            FlushMessage(err) => write!(f, "failed to flush fuse message: {err}"),
            MissingParameter => write!(f, "one or more parameters are missing"),
            InvalidHeaderLength => write!(f, "the `len` field of the header is too small"),
            InvalidCString(err) => write!(f, "a c string parameter is invalid: {err}"),
            InvalidCString2(err) => write!(f, "a c string parameter is invalid: {err}"),
            InvalidXattrSize((size, len)) => write!(
                f,
                "The `size` field of the `SetxattrIn` message does not match the length of the\
                 decoded value: size = {size}, value.len() = {len}"
            ),
            MissingExtension => write!(f, "one or more extensions are missing"),
        }
    }
}

pub type Result<T> = ::std::result::Result<T, Error>;
