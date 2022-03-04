namespace NOnion.Cells

open System.IO

open NOnion

type CellCreatedFast =
    private
        {
            Y: array<byte>
            DerivativeKeyData: array<byte>
        }

    static member Deserialize(reader: BinaryReader) =
        {
            Y = reader.ReadBytes Constants.HashLength
            DerivativeKeyData = reader.ReadBytes Constants.HashLength
        }
        :> ICell

    interface ICell with

        member __.Command = 6uy

        member self.Serialize writer =
            writer.Write self.Y
            writer.Write self.DerivativeKeyData

    interface ICreatedCell with
        member self.ServerHandshake = self.Y

        member self.DerivativeKey = self.DerivativeKeyData
