namespace NOnion.Cells.Relay

open System.IO
open System.Text

open Org.BouncyCastle.Crypto.Parameters

open NOnion
open NOnion.Crypto
open NOnion.Utility

type RelayIntroAuthKey =
    | ED25519SHA3256 of array<byte>
    | Legacy

    static member FromBytes(reader: BinaryReader) =
        let authKeyType, data =
            reader.ReadByte(),
            BinaryIO.ReadBigEndianUInt16 reader |> int |> reader.ReadBytes

        match authKeyType with
        | 0uy
        | 1uy ->
            failwith
                "deserializtion failed, legacy auth keys are not implemented"
        | 2uy -> ED25519SHA3256 data
        | _ -> failwith "Unknown authentication key"

    member self.ToBytes() =
        match self with
        | Legacy ->
            failwith
                "serialization failed, legacy auth keys are not implemented"
        | ED25519SHA3256 data ->
            Array.concat
                [
                    Array.singleton 2uy
                    data.Length
                    |> uint16
                    |> IntegerSerialization.FromUInt16ToBigEndianByteArray
                    data
                ]

    member self.MacLength =
        match self with
        | Legacy ->
            failwith
                "unknown digest length, legacy auth keys are not implemented"
        | ED25519SHA3256 _ -> 32

    member self.SignatureLength =
        match self with
        | Legacy ->
            failwith
                "unknown signature length, legacy auth keys are not implemented"
        | ED25519SHA3256 _ -> 64

type RelayIntroExtension =
    {
        ExtensionType: byte
        ExtensionField: array<byte>
    }

    static member FromBytes(reader: BinaryReader) =
        {
            ExtensionType = reader.ReadByte()
            ExtensionField =
                BinaryIO.ReadBigEndianUInt16 reader |> int |> reader.ReadBytes
        }

    member self.ToBytes() =
        Array.concat
            [
                self.ExtensionType |> Array.singleton
                self.ExtensionField.Length |> byte |> Array.singleton
                self.ExtensionField
            ]

type RelayEstablishIntro =
    {
        AuthKey: RelayIntroAuthKey
        Extensions: List<RelayIntroExtension>
        HandshakeAuth: array<byte>
        Signature: array<byte>
    }

    static member Create
        (privateKey: Ed25519PrivateKeyParameters)
        (publicKey: Ed25519PublicKeyParameters)
        (keyMaterial: array<byte>)
        =
        let relayData =
            {
                RelayEstablishIntro.AuthKey =
                    publicKey.GetEncoded() |> RelayIntroAuthKey.ED25519SHA3256
                Extensions = List.empty
                HandshakeAuth = Array.empty
                Signature = Array.empty
            }

        let handshakeAuth =
            relayData.ToBytes false false
            |> HiddenServicesCipher.CalculateMacWithSHA3256 keyMaterial

        let relayData =
            { relayData with
                HandshakeAuth = handshakeAuth
            }

        let signature =
            Array.concat
                [
                    Constants.EstablishIntroDataPrefix
                    |> Encoding.ASCII.GetBytes
                    relayData.ToBytes true false
                ]
            |> HiddenServicesCipher.SignWithED25519 privateKey

        { relayData with
            Signature = signature
        }



    static member FromBytes(reader: BinaryReader) =
        let authKey = RelayIntroAuthKey.FromBytes reader

        let extensions =
            let extensionCount = reader.ReadByte()

            let rec readExtensionsList state remainingCount =
                if remainingCount = 0uy then
                    state
                else
                    readExtensionsList
                        ((RelayIntroExtension.FromBytes reader) :: state)
                        (remainingCount - 1uy)

            readExtensionsList List.empty extensionCount

        let handshakeAuth = reader.ReadBytes authKey.MacLength

        let signature =
            let sigLength = BinaryIO.ReadBigEndianUInt16 reader |> int

            if sigLength = authKey.SignatureLength then
                sigLength |> reader.ReadBytes
            else
                failwithf
                    "EstablishIntro deserialization failed, invalid signature size (expected %i, got %i)"
                    authKey.SignatureLength
                    sigLength

        {
            AuthKey = authKey
            Extensions = extensions
            HandshakeAuth = handshakeAuth
            Signature = signature
        }

    member self.ToBytes (serializeMac: bool) (serializeSignature: bool) =
        if serializeSignature
           && self.AuthKey.SignatureLength <> self.Signature.Length then
            failwithf
                "EstablishIntro serialization failed, signature should be %i bytes (was %i)"
                self.AuthKey.SignatureLength
                self.Signature.Length

        if serializeMac && self.AuthKey.MacLength <> self.HandshakeAuth.Length then
            failwithf
                "EstablishIntro serialization failed, digest should be %i bytes (was %i)"
                self.AuthKey.MacLength
                self.HandshakeAuth.Length

        let digestAndSignature =
            match serializeMac, serializeSignature with
            | true, true ->
                Array.concat
                    [
                        self.HandshakeAuth
                        self.Signature.Length
                        |> uint16
                        |> IntegerSerialization.FromUInt16ToBigEndianByteArray
                        self.Signature
                    ]
            | true, false -> self.HandshakeAuth
            | false, false -> Array.empty
            | _ -> failwith "Invalid serialization option"

        Array.concat
            [
                self.AuthKey.ToBytes()
                self.Extensions.Length |> byte |> Array.singleton
                self.Extensions
                |> List.map(fun ext -> ext.ToBytes())
                |> Array.concat
                digestAndSignature
            ]
