namespace NOnion.Utility

open System
open System.IO

[<AutoOpen>]
module BinaryIOExtensions =

    type BinaryWriter with

        member self.WriteUInt16BigEndian (num: uint16): unit =
            num.ToBigEndianByteArray () |> self.Write

        member self.WriteUInt32BigEndian (num: uint32): unit =
            num.ToBigEndianByteArray () |> self.Write

    type BinaryReader with

        member self.ReadBigEndianUInt16 (): uint16 =
            sizeof<uint16> |> self.ReadBytes |> UInt16.FromBigEndianByteArray

        member self.ReadBigEndianUInt32 (): uint32 =
            sizeof<uint32> |> self.ReadBytes |> UInt32.FromBigEndianByteArray
