namespace NOnion.Utility

open System.Collections.Generic

module ByteArrayUtil =
    let ByteArrayCompare (x: array<byte>) (y: array<byte>) =
        let xlen = x.Length
        let ylen = y.Length

        let len =
            if xlen < ylen then
                xlen
            else
                ylen

        let mutable index = 0
        let mutable result = 0

        while index < len do
            let diff = (int(x.[index])) - int(y.[index])

            if diff <> 0 then
                index <- len + 1 // breaks out of the loop, and signals that result is valid
                result <- diff
            else
                index <- index + 1

        if index > len then
            result
        else
            (xlen - ylen)

    type ByteArrayComparer() =
        interface IComparer<array<byte>> with
            member __.Compare(first, second) =
                ByteArrayCompare first second
