namespace NOnion.Utility

open System

open NOnion
open DateTimeUtils

module HiddenServicesUtility =
    let GetTimePeriod (liveConsensusValidAfter: DateTime) (hsDirInterval: int) =
        let liveConsensusValidAfterInMinutes =
            let validAfterSinceEpoch =
                GetTimeSpanSinceEpoch liveConsensusValidAfter

            validAfterSinceEpoch
                .Subtract(
                    Constants.RotationTimeOffset
                )
                .TotalMinutes
            |> int

        liveConsensusValidAfterInMinutes / hsDirInterval

    let GetStartTimeOfCurrentSRVProtocolRun
        (liveConsensusValidAfter: DateTime)
        (votingInterval: TimeSpan)
        =

        let totalRounds =
            Constants.SharedRandomNPhases * Constants.SharedRandomNRounds

        let unixLiveConsensusValidAfter =
            ToUnixTimestamp liveConsensusValidAfter

        let votingIntervalInSec = votingInterval.TotalSeconds |> uint

        let currRoundSlot =
            (unixLiveConsensusValidAfter / votingIntervalInSec) % totalRounds

        let timeElapsedSinceStartOfRun = currRoundSlot * votingIntervalInSec

        unixLiveConsensusValidAfter - timeElapsedSinceStartOfRun
        |> FromUnixTimestamp

    let GetStartTimeOfPreviousSRVProtocolRun
        (liveConsensusValidAfter: DateTime)
        (votingInterval: TimeSpan)
        =
        let totalRounds =
            Constants.SharedRandomNPhases * Constants.SharedRandomNRounds

        let votingIntervalInSec = votingInterval.TotalSeconds |> uint

        let currentRunStartTime =
            GetStartTimeOfCurrentSRVProtocolRun
                liveConsensusValidAfter
                votingInterval

        currentRunStartTime
        - (totalRounds * votingIntervalInSec |> float |> TimeSpan.FromSeconds)


    let private GetStartTimeOfNextTimePeriod
        (liveConsensusValidAfter: DateTime)
        (hsDirInterval: int)
        =
        let timePeriodNum =
            (GetTimePeriod liveConsensusValidAfter hsDirInterval) + 1

        Constants.UnixEpoch
        + Constants.RotationTimeOffset
        + TimeSpan.FromMinutes(timePeriodNum * hsDirInterval |> float)

    (*
     * Ported from https://github.com/torproject/tor/blob/aa28535f671152cfae763c254569a89317a91341/src/feature/hs/hs_common.c#L987
     * Return true if we are currently in the time segment between a new time
     * period and a new SRV (in the real network that happens between 12:00 and
     * 00:00 UTC). Here is a diagram showing exactly when this returns true:
     *
     *    +------------------------------------------------------------------+
     *    |                                                                  |
     *    | 00:00      12:00       00:00       12:00       00:00       12:00 |
     *    | SRV#1      TP#1        SRV#2       TP#2        SRV#3       TP#3  |
     *    |                                                                  |
     *    |  $==========|-----------$===========|-----------$===========|    |
     *    |             ^^^^^^^^^^^^            ^^^^^^^^^^^^                 |
     *    |                                                                  |
     *    +------------------------------------------------------------------+
     *)

    let InPeriodBetweenTPAndSRV
        (liveConsensusValidAfter: DateTime)
        (votingInterval: TimeSpan)
        (hsDirInterval: int)
        =
        let srvStartTime =
            GetStartTimeOfCurrentSRVProtocolRun
                liveConsensusValidAfter
                votingInterval

        let tpStartTime =
            GetStartTimeOfNextTimePeriod srvStartTime hsDirInterval

        not(
            liveConsensusValidAfter >= srvStartTime
            && liveConsensusValidAfter < tpStartTime
        )

    // https://github.com/torproject/torspec/blob/cb4ae84a20793a00f35a70aad5df47d4e4c7da7c/rend-spec-v3.txt#L2161
    let DecodeOnionUrl(url: string) =
        //Add a fake protocol
        let parsedUrl = Uri(sprintf "http://%s" url)

        let urlParts = parsedUrl.DnsSafeHost.Split '.'

        if urlParts.Length < 2 then
            failwith "Invalid onion service url"
        else
            //Remove subdomains and .onion suffix and decode
            let keyBytesOpt =
                urlParts
                |> Seq.tryItem(urlParts.Length - 2)
                |> Option.map Base32Util.DecodeBase32

            // PublicKey (32 bytes) + Checksum (2 bytes) + Version (1 byte)
            let expectedOnionUrlLength =
                Constants.HiddenServices.OnionUrl.PublicKeyLength
                + Constants.HiddenServices.OnionUrl.ChecksumLength
                + 1

            match keyBytesOpt with
            | Some keyBytes when keyBytes.Length = expectedOnionUrlLength ->
                keyBytes.[0 .. Constants.HiddenServices.OnionUrl.PublicKeyLength
                               - 1],
                parsedUrl.Port
            | _ -> failwith "Unable to decode onion service url"
