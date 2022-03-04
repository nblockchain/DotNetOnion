namespace NOnion.Utility

module SeqUtils =
    // Helper function copied from https://stackoverflow.com/a/21615676
    let Chunk chunkSize sequence =
        sequence
        |> Seq.mapi(fun i x -> i / chunkSize, x)
        |> Seq.groupBy fst
        |> Seq.map(fun (_, g) -> Seq.map snd g)

    let TakeRandom count sequence =
        sequence |> Seq.sortBy(fun _ -> System.Guid.NewGuid()) |> Seq.take count
