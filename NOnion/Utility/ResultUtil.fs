namespace NOnion.Utility

open Fsdk

//FIXME: for some reason FSharpUtil is in NOnion namespace instead of NOnion.Utility
open NOnion

// RequireQualifiedAccess is needed to prevent collision with
// Failure function that creates general exceptions

[<RequireQualifiedAccess>]
type internal OperationResult<'T> =
    | Ok of 'T
    | Failure of exn

[<AutoOpen>]
module internal ResultUtil =
    let UnwrapResult<'T>(resultObj: OperationResult<'T>) =
        match resultObj with
        | OperationResult.Ok result -> result
        | OperationResult.Failure ex -> raise <| FSharpUtil.ReRaise ex
