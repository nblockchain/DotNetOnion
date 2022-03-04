namespace NOnion.Cells

open System.IO

open NOnion

type CellCreateFast =
    {
        X: array<byte>
    }

    static member Deserialize(reader: BinaryReader) =
        {
            X = reader.ReadBytes Constants.HashLength
        }
        :> ICell

    interface ICell with

        member __.Command = 5uy

        member self.Serialize writer =
            writer.Write self.X
