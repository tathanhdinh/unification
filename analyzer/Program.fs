// Learn more about F# at http://fsharp.net
// See the 'F# Tutorial' project for more help.

type Instruction<'TAddress, 'TThreadID> = { Address: 'TAddress;
                                            NextAddress: 'TAddress;
                                            Mnemonic: string;
                                            ThreadId: 'TThreadID }

let parseTraceHeader (traceFileReader:System.IO.BinaryReader) =
  let addrint_size = traceFileReader.ReadByte ()
  let bool_size = traceFileReader.ReadByte ()
  let threadid_size = traceFileReader.ReadByte ()
  (addrint_size, bool_size, threadid_size)

(*=====================================================================================================================*)

let getTraceLength<'TAddress when 'TAddress : unmanaged> (traceFileReader:System.IO.BinaryReader) =
  // let trace_length:uint64 ref = ref (uint64 0)
  match typeof<'TAddress> with
    | t when t = typeof<uint32> ->
      let trace_length = ref (uint32 0)
      while (traceFileReader.BaseStream.Position <> traceFileReader.BaseStream.Length) do
        let instruction_length = traceFileReader.ReadUInt32 ()
        traceFileReader.BaseStream.Seek (int64 instruction_length, System.IO.SeekOrigin.Current) |> ignore
        trace_length := !trace_length + (uint32 1)
      unbox<'TAddress> !trace_length
    | t when t = typeof<uint64> ->
      let trace_length = ref (uint64 0)
      while (traceFileReader.BaseStream.Position <> traceFileReader.BaseStream.Length) do
        let instruction_length = traceFileReader.ReadUInt64 ()
        traceFileReader.BaseStream.Seek (int64 instruction_length, System.IO.SeekOrigin.Current) |> ignore
        trace_length := !trace_length + (uint64 1)
      unbox<'TAddress> !trace_length
    | _ -> failwith "unknown type parameter"

let getTraceLengthX86 (traceFileReader:System.IO.BinaryReader) =
  let trace_length:uint32 ref = ref (uint32 0)
  while (traceFileReader.BaseStream.Position <> traceFileReader.BaseStream.Length) do
    let instruction_length = traceFileReader.ReadUInt32 ()
    traceFileReader.BaseStream.Seek(int64 instruction_length, System.IO.SeekOrigin.Current) |> ignore
    trace_length := !trace_length + (uint32 1)
  !trace_length

let getTraceLengthX8664 (traceFileReader:System.IO.BinaryReader) =
 let trace_length:uint64 ref = ref (uint64 0)
 while (traceFileReader.BaseStream.Position <> traceFileReader.BaseStream.Length) do
   let instruction_length = traceFileReader.ReadUInt64 ()
   traceFileReader.BaseStream.Seek(int64 instruction_length, System.IO.SeekOrigin.Current) |> ignore
   trace_length := !trace_length + (uint64 1)
 !trace_length

(*=====================================================================================================================*)

let deserializeOpcode<'TAddress when 'TAddress : unmanaged> (traceFileReader:System.IO.BinaryReader) =
  let opcode_size =
    match typeof<'TAddress> with
      | t when t = typeof<uint32> -> int (traceFileReader.ReadUInt32 ())
      | t when t = typeof<uint64> -> int (traceFileReader.ReadUInt64 ())
      | _ -> failwith "unknown type parameter"
  let opcode_buffer = traceFileReader.ReadBytes opcode_size
  opcode_buffer

let deserializeOpcodeX8664 (traceFileReader:System.IO.BinaryReader) =
  let opcode_size = traceFileReader.ReadUInt64 ()
  // Printf.printfn "opcode size: %d" opcode_size
  let opcode_buffer = traceFileReader.ReadBytes (int opcode_size)
  opcode_buffer
  // (opcode_size, opcode_buffer)

(*=====================================================================================================================*)

let deserializeMnemonic<'TAddress when 'TAddress : unmanaged> (traceFileReader:System.IO.BinaryReader) =
  let mnemonic_len =
    match typeof<'TAddress> with
      | t when t = typeof<uint32> -> int (traceFileReader.ReadUInt32 ())
      | t when t = typeof<uint64> -> int (traceFileReader.ReadUInt64 ())
      | _ -> failwith "unknown type parameter"
  let mnemonic_str = traceFileReader.ReadBytes mnemonic_len
  System.Text.Encoding.ASCII.GetString mnemonic_str

let deserializeMnemonicX8664 (traceFileReader:System.IO.BinaryReader) =
  let mnemonic_len = traceFileReader.ReadUInt64 ()
  let mnemonic_str = traceFileReader.ReadBytes (int mnemonic_len)
  System.Text.Encoding.ASCII.GetString mnemonic_str

(*=====================================================================================================================*)

let deserializeRegMap<'TAddress> (traceFileReader:System.IO.BinaryReader) =
  let reg_map_len =
    match typeof<'TAddress> with
      | t when t = typeof<uint32> -> int (traceFileReader.ReadUInt32 ())
      | t when t = typeof<uint64> -> int (traceFileReader.ReadUInt64 ())
      | _ -> failwith "unknown type parameter"
  let reg_map_buffer = traceFileReader.ReadBytes reg_map_len
  reg_map_buffer

let deserializeRegMapX8664 (traceFileReader:System.IO.BinaryReader) =
  let reg_map_len = traceFileReader.ReadUInt64 ()
  // Printf.printfn "register map length: %d" reg_map_len
  let reg_map_buffer = traceFileReader.ReadBytes (int reg_map_len)
  (reg_map_len, reg_map_buffer)

(*=====================================================================================================================*)

let deserializeMemMap<'TAddress> (traceFileReader:System.IO.BinaryReader) =
  let mem_map_len =
    match typeof<'TAddress> with
      | t when t = typeof<uint32> -> int (traceFileReader.ReadUInt32 ())
      | t when t = typeof<uint64> -> int (traceFileReader.ReadUInt64 ())
      | _ -> failwith "unknown type parameter"
  let mem_map_buffer = traceFileReader.ReadBytes mem_map_len
  mem_map_buffer

let deserializeMemMapX8664 (traceFileReader:System.IO.BinaryReader) =
  let mem_map_len = traceFileReader.ReadUInt64 ()
  // Printf.printfn "memory map length: %d" mem_map_len
  let mem_map_buffer = traceFileReader.ReadBytes (int mem_map_len)
  (mem_map_len, mem_map_buffer)

(*=====================================================================================================================*)

let deserializeTrace<'TAddress when 'TAddress : unmanaged> (traceFileReader:System.IO.BinaryReader) =
  let trace = ResizeArray<_>()
  while (traceFileReader.BaseStream.Position <> traceFileReader.BaseStream.Length) do
    let serialized_length =
      match typeof<'TAddress> with
        | t when t = typeof<uint32> -> traceFileReader.ReadUInt32 () |> unbox<'TAddress>
        | t when t = typeof<uint64> -> traceFileReader.ReadUInt64 () |> unbox<'TAddress>
        | _ -> failwith "unknown type parameter"
    let address =
      match typeof<'TAddress> with
        | t when t = typeof<uint32> -> traceFileReader.ReadUInt32 () |> unbox<'TAddress>
        | t when t = typeof<uint64> -> traceFileReader.ReadUInt64 () |> unbox<'TAddress>
        | _ -> failwith "unknown type parameter"
    let next_address =
      match typeof<'TAddress> with
        | t when t = typeof<uint32> -> traceFileReader.ReadUInt32 () |> unbox<'TAddress>
        | t when t = typeof<uint64> -> traceFileReader.ReadUInt64 () |> unbox<'TAddress>
        | _ -> failwith "unknown type parameter"
    deserializeOpcode<'TAddress> traceFileReader |> ignore
    let mnemonic_string = deserializeMnemonic<'TAddress> traceFileReader
    deserializeRegMap<'TAddress> traceFileReader |> ignore
    deserializeRegMap<'TAddress> traceFileReader |> ignore
    deserializeMemMap<'TAddress> traceFileReader |> ignore
    deserializeMemMap<'TAddress> traceFileReader |> ignore
    let thread_id = traceFileReader.ReadUInt32 ()
    trace.Add { Address = address;
                NextAddress = next_address;
                Mnemonic = mnemonic_string;
                ThreadId = thread_id }
  trace

let deserializeTraceX8664 (traceFileReader:System.IO.BinaryReader) =
  let trace = ResizeArray<_>()
  while (traceFileReader.BaseStream.Position <> traceFileReader.BaseStream.Length) do
    let serialized_length = traceFileReader.ReadUInt64 ()
    // Printf.printfn "serialized length: %d" serialized_length
    let address = traceFileReader.ReadUInt64 ()
    // Printf.printfn "address: 0x%x" address
    let next_address = traceFileReader.ReadUInt64 ()
    // Printf.printfn "next address: 0x%x" next_address
    deserializeOpcodeX8664 traceFileReader |> ignore
    let mnemonic_string = deserializeMnemonicX8664 traceFileReader
    Printf.printfn "%s" mnemonic_string
    deserializeRegMapX8664 traceFileReader |> ignore
    deserializeRegMapX8664 traceFileReader |> ignore
    deserializeMemMapX8664 traceFileReader |> ignore
    deserializeMemMapX8664 traceFileReader |> ignore
    let thread_id = traceFileReader.ReadUInt32 ()
    // Printf.printfn "thread id: %d" thread_id
    trace.Add { Address = address;
                NextAddress = next_address;
                Mnemonic = mnemonic_string;
                ThreadId = thread_id }
  trace

(*=====================================================================================================================*)

let printTrace<'TAddress when 'TAddress : unmanaged> (trace:ResizeArray<Instruction<'TAddress, uint32>>) =
  for ins in trace do
    match typeof<'TAddress> with
      | t when t = typeof<uint32> -> Printf.printfn "0x%x %s" (unbox<uint32> ins.Address) ins.Mnemonic
      | t when t = typeof<uint64> -> Printf.printfn "0x%x %s" (unbox<uint64> ins.Address) ins.Mnemonic
      | _ -> failwith "unknown type parameter"
  Printf.printfn "%u instructions parsed" (ResizeArray.length trace)

let printTraceX8664 (trace:ResizeArray<Instruction<uint64, uint32>>) =
  for ins in trace do
    Printf.printfn "0x%x %s" ins.Address ins.Mnemonic
  Printf.printfn "%u instructions parsed" (ResizeArray.length trace)

(*=====================================================================================================================*)

[<EntryPoint>]
let main argv =
  if Array.length argv <> 1 then
    Printf.printfn "give a serialized trace file from the command line (e.g. analyzer trace_file)"
    0
  else
    use traceFileReader = new System.IO.BinaryReader(System.IO.File.OpenRead(argv.[0]))
    let (addrint_size, bool_size, threadid_size) = parseTraceHeader traceFileReader
    Printf.printfn "sizes: (ADDRINT: %d), (BOOL: %d), (THREADID: %d)" addrint_size bool_size threadid_size
    if addrint_size = (byte 8) then
      deserializeTrace<uint64> traceFileReader |> printTrace<uint64>
      // let trace_length = getTraceLength<uint64> traceFileReader
      // Printf.printfn "number of serialized instructions: %d" trace_length
    else
      // deserializeTrace<uint32> traceFileReader |> printTrace<uint32>
      let trace_length = getTraceLength<uint32> traceFileReader
      Printf.printfn "number of serialized instructions: %d" trace_length
    1
 // printfn "%A" argv
 // 0 // return an integer exit code
