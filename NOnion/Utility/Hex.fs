namespace NOnion.Utility

open System

[<RequireQualifiedAccess>]
module Hex =

    let FromByteArray (bytes: byte []): string =
        bytes
        |> Array.map (fun (x: byte) -> String.Format ("{0:X2}", x))
        |> String.concat String.Empty

    let ToByteArray (hex: string): byte [] =

        // validate hex length
        if hex.Length % 2 <> 0 then
            invalidArg "hex" "hex.Length is not even"

        // blit bytes to array
        let bytes = Array.create (hex.Length / 2) 0uy
        let mutable i = 0

        while i < bytes.Length do
            bytes.[i] <- Convert.ToByte (hex.Substring (i * 2, 2), 16)
            i <- i + 1

        bytes
