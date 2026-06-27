// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

//! Shared multi-round broadcast session helpers for VRF WASM bindings.

use serde::{de::DeserializeOwned, Serialize};

use crate::message::{Message, MessageRouting};

/// Decode inbound WASM messages into protocol payloads.
pub(crate) fn decode_messages<T: DeserializeOwned>(
    msgs: &[Message],
) -> Vec<T> {
    Message::decode_vector(msgs)
}

/// Encode one or more outbound protocol payloads as WASM messages.
pub(crate) fn encode_messages<T: Serialize + MessageRouting>(
    msgs: Vec<T>,
) -> Vec<Message> {
    Message::encode_vector(msgs)
}

/// Encode a single outbound broadcast payload.
pub(crate) fn encode_message<T: Serialize + MessageRouting>(
    msg: T,
) -> Message {
    Message::new(msg)
}

/// Drop this party's own message from a batch (VRF DKG / eval round-1 inbound).
pub(crate) fn peer_messages<T>(messages: Vec<T>, party_id: u8) -> Vec<T>
where
    T: PartyMessage,
{
    messages
        .into_iter()
        .filter(|m| m.party_id() != party_id)
        .collect()
}

pub(crate) trait PartyMessage {
    fn party_id(&self) -> u8;
}
