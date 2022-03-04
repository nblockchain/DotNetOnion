namespace NOnion.Network

type TorWindow(start: int, increment: int) =

    let mutable package = start
    let mutable delivery = start
    let start = start
    let windowLock = obj()

    member __.NeedSendme() =
        let safeCheck() =
            if delivery > (start - increment) then
                false
            else
                delivery <- delivery + increment
                true

        lock windowLock safeCheck

    member __.DeliverDecrease() =
        let safeDecrease() =
            delivery <- delivery - 1

        lock windowLock safeDecrease

    member __.PackageDecrease() =
        let safeDecrease() =
            package <- package - 1

        lock windowLock safeDecrease

    member __.PackageIncrease() =
        let safeIncrease() =
            package <- package + increment

        lock windowLock safeIncrease
