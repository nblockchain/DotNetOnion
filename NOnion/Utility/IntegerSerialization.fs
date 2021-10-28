// NOTE: determine if it is actually useful to have a Utility namespace as opposed to just inhabiting NOnion.
namespace NOnion.Utility

open System

module IntegerSerialization =

    let private _someValue = 1

    let FromUInt16ToBigEndianByteArray (value: uint16) : array<byte> =
        let maybeLEbytes = BitConverter.GetBytes value

        if BitConverter.IsLittleEndian then
            Array.rev maybeLEbytes
        else
            maybeLEbytes

    let FromBigEndianByteArrayToUInt16 (bytes: array<byte>) : uint16 =
        let bytesForBitConverter =
            if BitConverter.IsLittleEndian then
                Array.rev bytes
            else
                bytes

        BitConverter.ToUInt16 (bytesForBitConverter, 0)

    let FromUInt32ToBigEndianByteArray (value: uint32) : array<byte> =
        let maybeLEbytes = BitConverter.GetBytes value

        if BitConverter.IsLittleEndian then
            Array.rev maybeLEbytes
        else
            maybeLEbytes

    let FromBigEndianByteArrayToUInt32 (bytes: array<byte>) : uint32 =
        let bytesForBitConverter =
            if BitConverter.IsLittleEndian then
                Array.rev bytes
            else
                bytes

        BitConverter.ToUInt32 (bytesForBitConverter, 0)

    let FromUInt64ToBigEndianByteArray (value: uint64) : array<byte> =
        let maybeLEbytes = BitConverter.GetBytes value

        if BitConverter.IsLittleEndian then
            Array.rev maybeLEbytes
        else
            maybeLEbytes
