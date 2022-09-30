// Base32 implementation from http://www.fssnip.net/7PR/title/Base64-Base32-Base16-encoding-and-decoding
namespace NOnion.Utility

module Base32Util =
    let EncodeBase32(data: array<byte>) =
        let quintupletToList ending (x0, x1, x2, x3, x4) =
            // RFC 4648: The Base 32 Alphabet
            let alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567="

            // RFC 4648: The "Extended Hex" Base 32 Alphabet
            // let A = "0123456789ABCDEFGHIJKLMNOPQRSTUV="

            let quintuplet =
                (int64 x0 <<< 32)
                ||| (int64 x1 <<< 24)
                ||| (int64 x2 <<< 16)
                ||| (int64 x3 <<< 8)
                ||| (int64 x4)

            let a0 = (quintuplet &&& 0xF800000000L) >>> 35 |> int
            let a1 = (quintuplet &&& 0x07C0000000L) >>> 30 |> int
            let a2 = (quintuplet &&& 0x003E000000L) >>> 25 |> int
            let a3 = (quintuplet &&& 0x0001F00000L) >>> 20 |> int
            let a4 = (quintuplet &&& 0x00000F8000L) >>> 15 |> int
            let a5 = (quintuplet &&& 0x0000007C00L) >>> 10 |> int
            let a6 = (quintuplet &&& 0x00000003E0L) >>> 5 |> int
            let a7 = (quintuplet &&& 0x000000001FL) |> int

            match ending with
            | 1 ->
                [
                    alphabet.[a0]
                    alphabet.[a1]
                    '='
                    '='
                    '='
                    '='
                    '='
                    '='
                ] // 01======
            | 2 ->
                [
                    alphabet.[a0]
                    alphabet.[a1]
                    alphabet.[a2]
                    alphabet.[a3]
                    '='
                    '='
                    '='
                    '='
                ] // 0123====
            | 3 ->
                [
                    alphabet.[a0]
                    alphabet.[a1]
                    alphabet.[a2]
                    alphabet.[a3]
                    alphabet.[a4]
                    '='
                    '='
                    '='
                ] // 01234===
            | 4 ->
                [
                    alphabet.[a0]
                    alphabet.[a1]
                    alphabet.[a2]
                    alphabet.[a3]
                    alphabet.[a4]
                    alphabet.[a5]
                    alphabet.[a6]
                    '='
                ] // 0123456=
            | _ ->
                [
                    alphabet.[a0]
                    alphabet.[a1]
                    alphabet.[a2]
                    alphabet.[a3]
                    alphabet.[a4]
                    alphabet.[a5]
                    alphabet.[a6]
                    alphabet.[a7]
                ] // 01234567

        let rec parse result input =
            match input with
            | x0 :: x1 :: x2 :: x3 :: x4 :: tail ->
                parse (result @ quintupletToList 5 (x0, x1, x2, x3, x4)) tail
            | x0 :: x1 :: x2 :: x3 :: [] ->
                result @ quintupletToList 4 (x0, x1, x2, x3, 0uy)
            | x0 :: x1 :: x2 :: [] ->
                result @ quintupletToList 3 (x0, x1, x2, 0uy, 0uy)
            | x0 :: x1 :: [] ->
                result @ quintupletToList 2 (x0, x1, 0uy, 0uy, 0uy)
            | x0 :: [] -> result @ quintupletToList 1 (x0, 0uy, 0uy, 0uy, 0uy)
            | [] -> result

        data |> Array.toList |> parse List.Empty |> List.toArray |> System.String.Concat

    /// Decodes a Base32 string to a UTF8 string
    let DecodeBase32 text =
        if (text: string).Length % 8 <> 0 then
            Array.empty
        else
            // RFC 4648: The Base 32 alphabet
            let alphabet =
                [
                    for char in "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567=" -> char
                ]
                |> List.mapi(fun idx char -> char, idx)
                |> Map.ofList

            // RFC 4648: The "Extended Hex" Base 32 alphabet
            // let A = [for c in "0123456789ABCDEFGHIJKLMNOPQRSTUV=" -> c]
            //         |> List.mapi (fun i a -> a, i)
            //         |> Map.ofList

            let (.@) (alphabet: Map<char, int>) key =
                try
                    alphabet.[System.Char.ToUpper key] |> int64
                with
                | _ -> 0L

            let octetToList ending (a0, a1, a2, a3, a4, a5, a6, a7) =
                let octet =
                    (alphabet .@ a0 &&& 0x1FL <<< 35)
                    ||| (alphabet .@ a1 &&& 0x1FL <<< 30)
                    ||| (alphabet .@ a2 &&& 0x1FL <<< 25)
                    ||| (alphabet .@ a3 &&& 0x1FL <<< 20)
                    ||| (alphabet .@ a4 &&& 0x1FL <<< 15)
                    ||| (alphabet .@ a5 &&& 0x1FL <<< 10)
                    ||| (alphabet .@ a6 &&& 0x1FL <<< 5)
                    ||| (alphabet .@ a7 &&& 0x1FL)

                let x0 = (octet &&& 0xFF00000000L) >>> 32 |> byte
                let x1 = (octet &&& 0x00FF000000L) >>> 24 |> byte
                let x2 = (octet &&& 0x0000FF0000L) >>> 16 |> byte
                let x3 = (octet &&& 0x000000FF00L) >>> 8 |> byte
                let x4 = (octet &&& 0x00000000FFL) |> byte

                match ending with
                | 2 -> x0 :: List.empty
                | 4 -> x0 :: x1 :: List.empty
                | 5 -> x0 :: x1 :: x2 :: List.empty
                | 7 -> x0 :: x1 :: x2 :: x3 :: List.empty
                | _ -> x0 :: x1 :: x2 :: x3 :: x4 :: List.empty

            let rec parse result input =
                match input with
                | a0 :: a1 :: '=' :: '=' :: '=' :: '=' :: '=' :: '=' :: _ ->
                    result
                    @ octetToList 2 (a0, a1, '=', '=', '=', '=', '=', '=')
                | a0 :: a1 :: a2 :: a3 :: '=' :: '=' :: '=' :: '=' :: _ ->
                    result @ octetToList 4 (a0, a1, a2, a3, '=', '=', '=', '=')
                | a0 :: a1 :: a2 :: a3 :: a4 :: '=' :: '=' :: '=' :: _ ->
                    result @ octetToList 5 (a0, a1, a2, a3, a4, '=', '=', '=')
                | a0 :: a1 :: a2 :: a3 :: a4 :: a5 :: a6 :: '=' :: _ ->
                    result @ octetToList 7 (a0, a1, a2, a3, a4, a5, a6, '=')
                | a0 :: a1 :: a2 :: a3 :: a4 :: a5 :: a6 :: a7 :: tail ->
                    parse
                        (result @ octetToList 8 (a0, a1, a2, a3, a4, a5, a6, a7))
                        tail
                | _ -> result

            [ for c in text -> c ] |> parse List.Empty |> List.toArray
