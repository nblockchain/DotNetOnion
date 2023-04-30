namespace NOnion.Utility

open System
open System.Runtime.ExceptionServices

open FSharpx.Collections

open NOnion

module FSharpUtil =
    //Implementation copied from https://github.com/nblockchain/geewallet/blob/master/src/GWallet.Backend/FSharpUtil.fs
    let ReRaise(ex: Exception) : Exception =
        (ExceptionDispatchInfo.Capture ex).Throw()
        failwith "Should be unreachable"
        ex

    let rec public FindException<'T when 'T :> Exception>
        (ex: Exception)
        : Option<'T> =
        let rec findExInSeq(sq: seq<Exception>) =
            match Seq.tryHeadTail sq with
            | Some(head, tail) ->
                match FindException head with
                | Some ex -> Some ex
                | None -> findExInSeq <| tail
            | None -> None

        if isNull ex then
            None
        else
            match ex with
            | :? 'T as specificEx -> Some specificEx
            | :? AggregateException as aggEx ->
                findExInSeq aggEx.InnerExceptions
            | _ -> FindException<'T> ex.InnerException

    type private Either<'Val, 'Err when 'Err :> Exception> =
        | FailureResult of 'Err
        | SuccessfulValue of 'Val

    let WithTimeout (timeSpan: TimeSpan) (job: Async<'R>) : Async<'R> =
        async {
            let read =
                async {
                    let! value = job
                    return value |> SuccessfulValue |> Some
                }

            let delay =
                async {
                    let total = int timeSpan.TotalMilliseconds
                    do! Async.Sleep total
                    return FailureResult <| TimeoutException() |> Some
                }

            let! dummyOption = Async.Choice([ read; delay ])

            match dummyOption with
            | Some theResult ->
                match theResult with
                | SuccessfulValue r -> return r
                | FailureResult _ -> return raise <| TimeoutErrorException()
            | None ->
                // none of the jobs passed to Async.Choice returns None
                return failwith "unreachable"
        }

    let Retry<'E1, 'E2 when 'E1 :> Exception and 'E2 :> Exception>
        (jobToRetry: Async<unit>)
        (maxRetryCount: int)
        =
        let rec retryLoop(tryNumber: int) =
            async {
                try
                    do! jobToRetry
                with
                | :? 'E1
                | :? 'E2 as ex ->
                    if tryNumber < maxRetryCount then
                        return! retryLoop(tryNumber + 1)
                    else
                        sprintf
                            "Maximum retry count reached, ex = %s"
                            (ex.ToString())
                        |> TorLogger.Log

                        return raise <| ReRaise ex
                | ex ->
                    sprintf
                        "Unexpected exception happened in the retry loop, ex = %s"
                        (ex.ToString())
                    |> TorLogger.Log

                    return raise <| ReRaise ex
            }

        retryLoop 0

    let UnwrapOption<'T> (opt: Option<'T>) (msg: string) : 'T =
        match opt with
        | Some value -> value
        | None -> failwith <| sprintf "error unwrapping Option: %s" msg
