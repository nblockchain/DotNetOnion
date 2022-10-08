﻿namespace NOnion.Cells.Relay

open System.IO

open NOnion
open NOnion.Cells
open NOnion.Utility

type RelayIntroduceInnerData =
    {
        RendezvousCookie: array<byte>
        Extensions: List<RelayIntroExtension>
        OnionKey: array<byte>
        RendezvousLinkSpecifiers: List<LinkSpecifier>
    }

    static member Deserialize(reader: BinaryReader) =
        let cookie = reader.ReadBytes Constants.RendezvousCookieLength

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

        let onionKeyType = reader.ReadByte() |> int

        if onionKeyType <> Constants.RelayIntroduceKeyType then
            failwith "Unsupported onion key"

        let onionKeyLength = BinaryIO.ReadBigEndianUInt16 reader |> int

        if onionKeyLength <> Constants.NTorPublicKeyLength then
            failwith "Invalid onion key length"

        let onionKey = reader.ReadBytes Constants.NTorPublicKeyLength

        let rec readLinkSpecifier (n: byte) (state: List<LinkSpecifier>) =
            if n = 0uy then
                state
            else
                LinkSpecifier.Deserialize reader
                |> List.singleton
                |> List.append state
                |> readLinkSpecifier(n - 1uy)

        let linkSpecifiers = readLinkSpecifier (reader.ReadByte()) List.empty

        {
            RendezvousCookie = cookie
            RendezvousLinkSpecifiers = linkSpecifiers
            OnionKey = onionKey
            Extensions = extensions
        }

    member self.ToBytes() =
        Array.concat
            [
                self.RendezvousCookie
                self.Extensions.Length |> byte |> Array.singleton
                self.Extensions
                |> List.map(fun ext -> ext.ToBytes())
                |> Array.concat
                Array.singleton 1uy
                self.OnionKey.Length
                |> uint16
                |> IntegerSerialization.FromUInt16ToBigEndianByteArray
                self.OnionKey
                self.RendezvousLinkSpecifiers.Length |> byte |> Array.singleton
                self.RendezvousLinkSpecifiers
                |> List.map(fun link -> link.ToBytes())
                |> Array.concat
            ]

type RelayIntroduce =
    {
        AuthKey: RelayIntroAuthKey
        Extensions: List<RelayIntroExtension>
        ClientPublicKey: array<byte>
        EncryptedData: array<byte>
        Mac: array<byte>
    }

    static member FromBytes(reader: BinaryReader) =
        let legacyKeyId = reader.ReadBytes 20

        if not(legacyKeyId |> Array.forall(fun byte -> byte = 0uy)) then
            failwith "Legacy key id should be all zeroes"

        let authKey = RelayIntroAuthKey.FromBytes reader

        let extensions =
            let extensionCount = reader.ReadByte()

            let rec readExtensionsList state remainingCount =
                if remainingCount = 0uy then
                    state
                else
                    readExtensionsList
                        ((RelayIntroExtension.FromBytes reader)::state)
                        (remainingCount - 1uy)

            readExtensionsList List.empty extensionCount

        let remainingDataSize =
            reader.BaseStream.Length - reader.BaseStream.Position |> int

        let encryptedDataSize =
            remainingDataSize
            - authKey.MacLength
            - Constants.NTorPublicKeyLength

        let publicKey = reader.ReadBytes Constants.NTorPublicKeyLength

        let encryptedData = encryptedDataSize |> reader.ReadBytes

        let mac = reader.ReadBytes authKey.MacLength

        {
            AuthKey = authKey
            Extensions = extensions
            ClientPublicKey = publicKey
            EncryptedData = encryptedData
            Mac = mac
        }

    member self.ToBytes() =
        Array.concat
            [
                Array.zeroCreate 20
                self.AuthKey.ToBytes()
                self.Extensions.Length |> byte |> Array.singleton
                self.Extensions
                |> List.map(fun ext -> ext.ToBytes())
                |> Array.concat
                self.ClientPublicKey
                self.EncryptedData
                self.Mac
            ]
