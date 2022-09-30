namespace NOnion.Cells

open System.IO

open FSharpx.Collections

open NOnion.Utility.BinaryIO

type RouterAddress =
    {
        Type: byte
        Value: array<byte>
    }

type CellNetInfo =
    {
        Time: uint32
        MyAddresses: seq<RouterAddress>
        OtherAddress: RouterAddress
    }

    static member Deserialize(reader: BinaryReader) =

        let readAddress() : RouterAddress =
            {
                RouterAddress.Type = reader.ReadByte()
                Value = reader.ReadByte() |> int |> reader.ReadBytes
            }

        let rec readAddresses addresses remainingCount =
            if remainingCount = 0uy then
                addresses
            else
                readAddresses
                    (readAddress() :: addresses)
                    (remainingCount - 1uy)

        let time = ReadBigEndianUInt32 reader
        let otherAddress = readAddress()
        let myAddressesCount = reader.ReadByte()
        let myAddresses = readAddresses List.Empty myAddressesCount |> Seq.rev

        {
            Time = time
            MyAddresses = myAddresses
            OtherAddress = otherAddress
        }
        :> ICell

    interface ICell with

        member __.Command = 8uy

        member self.Serialize writer =

            let writeAddress(addr: RouterAddress) =
                writer.Write addr.Type
                addr.Value.Length |> byte |> writer.Write
                writer.Write addr.Value

            let rec writeAddresses(addresses: seq<RouterAddress>) =
                match Seq.tryHeadTail addresses with
                | None -> ()
                | Some(addr, nextAddresses) ->
                    writeAddress addr
                    writeAddresses nextAddresses

            WriteUInt32BigEndian writer self.Time
            writeAddress self.OtherAddress
            self.MyAddresses |> Seq.length |> byte |> writer.Write
            writeAddresses self.MyAddresses
