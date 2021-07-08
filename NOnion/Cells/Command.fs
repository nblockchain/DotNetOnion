namespace NOnion.Cells

open System
open System.IO

[<RequireQualifiedAccess>]
module Command =

    [<Literal>]
    let Certs = 129uy

    [<Literal>]
    let AuthChallenge = 130uy

    [<Literal>]
    let Version = 7uy

    [<Literal>]
    let NetInfo = 8uy

    [<Literal>]
    let CreateFast = 5uy

    [<Literal>]
    let CreatedFast = 6uy

    let IsVariableLength (command: byte): bool =
        command = 7uy || command >= 128uy

    /// Serialize a cell, assuming its command has already been written.
    /// TODO: make a more independent Cell.Serialize function that writes its own command byte?
    let SerializeCell writer (cell: ICell) =
        cell.Serialize writer

    /// Deserialize a cell of the given command type that has already been read.
    /// TODO: make a more independent Cell.Deserialize function that reads its own command byte?
    let DeserializeCell (reader: BinaryReader) (command: byte): ICell =
        match command with
        | Certs -> CellCerts.Deserialize reader
        | AuthChallenge -> CellAuthChallenge.Deserialize reader
        | Version -> CellVersions.Deserialize reader
        | NetInfo -> CellNetInfo.Deserialize reader
        | CreateFast -> CellCreateFast.Deserialize reader
        | CreatedFast -> CellCreatedFast.Deserialize reader
        | _ -> raise <| NotImplementedException ()
