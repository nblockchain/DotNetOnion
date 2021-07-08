// NOTE: determine if it is actually useful to have a Utility namespace as opposed to just inhabiting NOnion.
namespace NOnion.Utility

open System

[<AutoOpen>]
module IntegerExtensions =

    type UInt16 with

        member self.ToBigEndianByteArray (): array<byte> =
            let maybeLEbytes = BitConverter.GetBytes self

            if BitConverter.IsLittleEndian then
                Array.rev maybeLEbytes
            else
                maybeLEbytes

        static member FromBigEndianByteArray (bytes: array<byte>): uint16 =
            let bytesForBitConverter =
                if BitConverter.IsLittleEndian then
                    Array.rev bytes
                else
                    bytes

            BitConverter.ToUInt16 (bytesForBitConverter, 0)

    type UInt32 with

        member self.ToBigEndianByteArray (): array<byte> =
            let maybeLEbytes = BitConverter.GetBytes self

            if BitConverter.IsLittleEndian then
                Array.rev maybeLEbytes
            else
                maybeLEbytes

        static member FromBigEndianByteArray (bytes: array<byte>): uint32 =
            let bytesForBitConverter =
                if BitConverter.IsLittleEndian then
                    Array.rev bytes
                else
                    bytes

            BitConverter.ToUInt32 (bytesForBitConverter, 0)
