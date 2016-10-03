type Instruction<'TAddress> = { Address : 'TAddress;
                                NextAddress : 'TAddress;
                                Mnemonic : string;
                                ThreadId : uint32; }

type NativeTrace<'TAddress> = ResizeArray<Instruction<'TAddress>>

type Location<'TAddress when 'TAddress : comparison> = Map<'TAddress, Instruction<'TAddress> list>

type BasicBlock<'TAddress when 'TAddress : comparison> = Location<'TAddress> list 

[<EntryPoint>]
let main argv = 
    printfn "%A" argv
    0 // return an integer exit code
