namespace NOnion.Network

type TorWindow (start: int, increament: int) =

    let mutable package = start
    let mutable delivery = start
    let increament = increament
    let start = start
    let windowLock = obj ()

    member __.NeedSendme () =
        let safeCheck () =
            if delivery > (start - increament) then
                false
            else
                delivery <- delivery + increament
                true

        lock windowLock safeCheck

    member __.DeliverDecrease () =
        let safeDecrease () =
            delivery <- delivery - 1

        lock windowLock safeDecrease

    member __.PackageDecrease () =
        let safeDecrease () =
            package <- package - 1

        lock windowLock safeDecrease

    member __.PackageIncrease () =
        let safeIncrease () =
            package <- package + increament

        lock windowLock safeIncrease

    member private __.Foo_Bar () =
        ()

    member private __.foo_bar () =
        ()

    member private __.Baz () =
        ()
