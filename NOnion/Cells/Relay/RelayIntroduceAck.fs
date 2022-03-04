namespace NOnion.Cells.Relay

open System.IO

open NOnion
open NOnion.Cells
open NOnion.Utility


type RelayIntroduceStatus =
    | Success = 0us
    | Failure = 1us
    | BadMessageFormat = 2us
    | RelayFailed = 3us

type RelayIntroduceAck =
    {
        Status: RelayIntroduceStatus
        Extensions: List<RelayIntroExtension>
    }

    static member FromBytes(reader: BinaryReader) =
        let status =
            reader.ReadBytes 2
            |> IntegerSerialization.FromBigEndianByteArrayToUInt16
            |> LanguagePrimitives.EnumOfValue<uint16, RelayIntroduceStatus>

        let extensions =
            let extensionCount = reader.ReadByte()

            let rec readExtensionsList state remainingCount =
                if remainingCount = 0uy then
                    state
                else
                    readExtensionsList
                        (state
                         @ List.singleton(RelayIntroExtension.FromBytes reader))
                        (remainingCount - 1uy)

            readExtensionsList List.empty extensionCount

        {
            Status = status
            Extensions = extensions
        }

    member self.ToBytes() =
        Array.concat
            [
                self.Status
                |> uint16
                |> IntegerSerialization.FromUInt16ToBigEndianByteArray
                self.Extensions.Length |> byte |> Array.singleton
                self.Extensions
                |> List.map(fun ext -> ext.ToBytes())
                |> Array.concat
            ]
