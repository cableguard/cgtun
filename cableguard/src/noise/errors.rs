// Copyright (c) 2023 cableguard, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

#[derive(Debug)]
pub enum WireGuardError {
    DestinationBufferTooSmall,
    IncorrectPacketLength,
    UnexpectedPacket,
    WrongPacketType,
    WrongIndex,
    WrongKey,
    InvalidTai64nTimestamp,
    WrongTai64nTimestamp,
    InvalidMac,
    InvalidAeadTag,
    InvalidCounter,
    DuplicateCounter,
    InvalidPacket,
    NoCurrentSession,
    LockFailed,
    ConnectionExpired,
    UnderLoad,
    PeerEd25519PublicKeyParsingFailure,
    PeerEd25519SignatureVerificationFailure,
    PeerEd25519SignatureParsingFailure,
}
