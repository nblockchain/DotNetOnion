namespace NOnion.Cells

open System.IO

open FSharpx.Collections

open NOnion.Utility.BinaryIO

type CellVersions =
    {
        Versions: seq<uint16>
    }

    static member Deserialize(reader: BinaryReader) =

        let rec readVersions versions =
            if (reader.BaseStream.Length - reader.BaseStream.Position) % 2L
               <> 0L then
                failwith
                    "Version packet payload is invalid, payload length should be divisible by 2"

            if reader.BaseStream.Length = reader.BaseStream.Position then
                versions
            else
                readVersions((ReadBigEndianUInt16 reader) :: versions)

        let versions = readVersions List.empty |> Seq.rev

        {
            Versions = versions
        }
        :> ICell

    interface ICell with

        member __.Command = 7uy

        member self.Serialize writer =

            let rec writeVersions(versions: seq<uint16>) =
                match Seq.tryHeadTail versions with
                | None -> ()
                | Some(version, nextVersions) ->
                    WriteUInt16BigEndian writer version
                    writeVersions nextVersions

            writeVersions self.Versions
