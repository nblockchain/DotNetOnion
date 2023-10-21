namespace NOnion.Utility

open System

open Fsdk

open NOnion

module AsyncUtil =
    let WithTimeout (timeSpan: TimeSpan) (job: Async<'R>) : Async<'R> =
        async {
            let! result = FSharpUtil.WithTimeout timeSpan job

            match result with
            | Some value -> return value
            | None -> return raise <| TimeoutErrorException()
        }

    let Retry<'TEx when 'TEx :> Exception>
        (jobToRetry: Async<unit>)
        (maxRetryCount: int)
        =
        async {
            try
                do!
                    FSharpUtil.Retry<_, 'TEx>
                        (fun () -> jobToRetry)
                        maxRetryCount
            with
            | :? 'TEx as ex ->
                sprintf "Maximum retry count reached, ex = %s" (ex.ToString())
                |> TorLogger.Log

                return raise <| FSharpUtil.ReRaise ex
            | ex ->
                sprintf
                    "Unexpected exception happened in the retry loop, ex = %s"
                    (ex.ToString())
                |> TorLogger.Log

                return raise <| FSharpUtil.ReRaise ex
        }

    let UnwrapOption<'T> (opt: Option<'T>) (msg: string) : 'T =
        match opt with
        | Some value -> value
        | None -> failwith <| sprintf "error unwrapping Option: %s" msg
