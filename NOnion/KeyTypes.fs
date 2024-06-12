namespace NOnion

open Org.BouncyCastle.Crypto.Parameters


type ExpandedEd25519PrivateKey(bytes: array<byte>) =
    do
        if bytes.Length <> Constants.ExpandedEd25519PrivateKeyLength then
            failwithf
                "Invalid private key (length=%d), %d expected"
                bytes.Length
                Constants.ExpandedEd25519PrivateKeyLength

    member self.ToByteArray() =
        bytes

[<RequireQualifiedAccess>]
type Ed25519PrivateKey =
    | Normal of Ed25519PrivateKeyParameters
    | Expanded of ExpandedEd25519PrivateKey

    static member FromBytes(bytes: array<byte>) : Ed25519PrivateKey =
        if bytes.Length = Constants.ExpandedEd25519PrivateKeyLength then
            Expanded <| ExpandedEd25519PrivateKey bytes
        elif bytes.Length = Constants.Ed25519PrivateKeyLength then
            Normal <| Ed25519PrivateKeyParameters(bytes, 0)
        else
            failwithf
                "Invalid private key (length=%d), private key should either be %d (standard ed25519) or %d bytes (expanded ed25519 key)"
                bytes.Length
                Constants.Ed25519PrivateKeyLength
                Constants.ExpandedEd25519PrivateKeyLength

    member self.ToByteArray() =
        match self with
        | Normal key -> key.GetEncoded()
        | Expanded key -> key.ToByteArray()

type ED25519PublicKey =
    | ED25519PublicKey of Ed25519PublicKeyParameters

    static member FromBytes(bytes: array<byte>) : ED25519PublicKey =
        ED25519PublicKey <| Ed25519PublicKeyParameters(bytes, 0)

    member self.ToByteArray() =
        match self with
        | ED25519PublicKey publicKeyParams -> publicKeyParams.GetEncoded()

type NTorOnionKey(bytes: array<byte>) =
    do
        if bytes.Length <> Constants.NTorPublicKeyLength then
            failwithf
                "Invalid onion key length, expected %d, got %d"
                Constants.NTorPublicKeyLength
                bytes.Length

    member self.ToByteArray() =
        bytes

/// Digest of identity key.
type Fingerprint(bytes: array<byte>) =
    do
        if bytes.Length <> Constants.FingerprintLength then
            failwithf
                "Invalid fingerprint (identity key digest) length, expected %d, got %d"
                Constants.FingerprintLength
                bytes.Length

    member self.ToByteArray() =
        bytes
