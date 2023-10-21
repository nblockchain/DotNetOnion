namespace NOnion.Utility

open System.Net.Sockets

open Fsdk

open NOnion

module internal MailboxResultUtil =
    let HandleError<'T>
        exn
        (replyChannel: AsyncReplyChannel<OperationResult<'T>>)
        =
        match FSharpUtil.FindException<SocketException> exn with
        | Some socketExn ->
            NOnionSocketException socketExn :> exn
            |> OperationResult.Failure
            |> replyChannel.Reply
        | None -> OperationResult.Failure exn |> replyChannel.Reply

    let TryExecuteAsyncAndReplyAsResult<'T>
        (replyChannel: AsyncReplyChannel<OperationResult<'T>>)
        (job: Async<'T>)
        =
        async {
            try
                let! result = job
                OperationResult.Ok result |> replyChannel.Reply
            with
            | exn -> HandleError exn replyChannel
        }

    let TryExecuteAndReplyAsResult<'T>
        (replyChannel: AsyncReplyChannel<OperationResult<'T>>)
        (job: unit -> 'T)
        =
        try
            let result = job()
            OperationResult.Ok result |> replyChannel.Reply
        with
        | exn -> HandleError exn replyChannel
