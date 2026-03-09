//! Serialization and deserialization utilities for group elements and scalars.
//!
//! This module provides functions to convert group elements and scalars to and from
//! byte representations using canonical encodings.

use alloc::vec::Vec;
use group::prime::PrimeGroup;
use spongefish::{NargDeserialize, NargSerialize};

use crate::errors::Error;

/// Get the serialized length of a group element in bytes.
///
/// # Returns
/// The number of bytes required to serialize a group element.
pub fn group_elt_serialized_len<G: PrimeGroup>() -> usize {
    G::Repr::default().as_ref().len()
}

pub(crate) fn serialize_messages_into<T: NargSerialize>(messages: &[T], out: &mut Vec<u8>) {
    for message in messages {
        message.serialize_into_narg(out);
    }
}

pub(crate) fn serialize_messages<T: NargSerialize>(messages: &[T]) -> Vec<u8> {
    let mut out = Vec::new();
    serialize_messages_into(messages, &mut out);
    out
}

pub(crate) fn deserialize_messages<T: NargDeserialize>(
    len: usize,
    buf: &mut &[u8],
) -> Result<Vec<T>, Error> {
    let mut out = Vec::with_capacity(len);
    for _ in 0..len {
        out.push(T::deserialize_from_narg(buf).map_err(|_| Error::VerificationFailure)?);
    }
    Ok(out)
}
