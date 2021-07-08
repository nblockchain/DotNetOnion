namespace NOnion.Cells

open System.IO

open NOnion
open NOnion.Utility

type CellAuthChallenge =
    {
        Challenge: array<byte>
        Methods: seq<uint16>
    }

    static member Deserialize (reader: BinaryReader) =

        let rec readMethod methods n =
            if n = 0 then
                methods
            else
                readMethod (methods @ [ reader.ReadBigEndianUInt16 () ]) (n - 1)

        let challenge = reader.ReadBytes Constants.ChallangeLength
        let methodsCount = reader.ReadBigEndianUInt16 () |> int
        let methods = readMethod [] methodsCount

        {
            Challenge = challenge
            Methods = methods
        }
        :> ICell

    interface ICell with

        member __.Command = 130uy

        member self.Serialize writer =

            let rec writeMethods (methods: seq<uint16>) =
                match Seq.tryHead methods with
                | None -> ()
                | Some method ->
                    writer.WriteUInt16BigEndian method
                    methods |> Seq.tail |> writeMethods

            writer.Write self.Challenge
            self.Methods |> Seq.length |> uint16 |> writer.WriteUInt16BigEndian
            writeMethods self.Methods
