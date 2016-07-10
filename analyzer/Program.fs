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

let getTraceLengthX8664 (traceFileReader:System.IO.BinaryReader) =
 let trace_length:uint64 ref = ref (uint64 0)
 while (traceFileReader.BaseStream.Position <> traceFileReader.BaseStream.Length) do
   let instruction_length = traceFileReader.ReadUInt64 ()
   traceFileReader.BaseStream.Seek(int64 instruction_length, System.IO.SeekOrigin.Current) |> ignore
   trace_length := !trace_length + (uint64 1)
 !trace_length

let deserializeOpcodeX8664 (traceFileReader:System.IO.BinaryReader) =
  let opcode_size = traceFileReader.ReadUInt64 ()
  Printf.printfn "opcode size: %d" opcode_size
  // let opcode_buffer = Array.zeroCreate (int opcode_size)
  let opcode_buffer = traceFileReader.ReadBytes (int opcode_size)
  (opcode_size, opcode_buffer)

let deserializeMnemonicX8664 (traceFileReader:System.IO.BinaryReader) =
  let mnemonic_len = traceFileReader.ReadUInt64 ()
  Printf.printfn "mnemonic length: %d" mnemonic_len
  let mnemonic_str = traceFileReader.ReadBytes (int mnemonic_len)
  System.Text.Encoding.ASCII.GetString mnemonic_str
  // (mnemonic_len, mnemonic_str)

let deserializeRegMapX8664 (traceFileReader:System.IO.BinaryReader) =
  let reg_map_len = traceFileReader.ReadUInt64 ()
  Printf.printfn "register map length: %d" reg_map_len
  let reg_map_buffer = traceFileReader.ReadBytes (int reg_map_len)
  (reg_map_len, reg_map_buffer)

let deserializeMemMapX8664 (traceFileReader:System.IO.BinaryReader) =
  let mem_map_len = traceFileReader.ReadUInt64 ()
  Printf.printfn "memory map length: %d" mem_map_len
  let mem_map_buffer = traceFileReader.ReadBytes (int mem_map_len)
  (mem_map_len, mem_map_buffer)

let deserializeTraceX8664 (traceFileReader:System.IO.BinaryReader) =
  let trace = ResizeArray<_>()
  while (traceFileReader.BaseStream.Position <> traceFileReader.BaseStream.Length) do
    let serialized_length = traceFileReader.ReadUInt64 ()
    Printf.printfn "serialized length: %d" serialized_length
    let address = traceFileReader.ReadUInt64 ()
    Printf.printfn "address: 0x%x" address
    let next_address = traceFileReader.ReadUInt64 ()
    Printf.printfn "next address: 0x%x" next_address
    deserializeOpcodeX8664 traceFileReader |> ignore
    let mnemonic_string = deserializeMnemonicX8664 traceFileReader
    deserializeRegMapX8664 traceFileReader |> ignore
    deserializeRegMapX8664 traceFileReader |> ignore
    deserializeMemMapX8664 traceFileReader |> ignore
    deserializeMemMapX8664 traceFileReader |> ignore
    let thread_id = traceFileReader.ReadUInt64 ()
    Printf.printfn "thread id: %d" thread_id
    trace.Add { Address = address;
                NextAddress = next_address;
                Mnemonic = mnemonic_string;
                ThreadId = thread_id }
  trace

let printTraceX8664 (trace:ResizeArray<Instruction<uint64, uint64>>) =
  for ins in trace do
    Printf.printfn "0x%16x %s" ins.Address ins.Mnemonic

[<EntryPoint>]
let main argv =
  if Array.length argv <> 1 then
    Printf.printfn "give a serialized trace file from the command line (e.g. analyzer trace_file)"
    0
  else
    use traceFileReader = new System.IO.BinaryReader(System.IO.File.OpenRead(argv.[0]))
    let (addrint_size, bool_size, threadid_size) = parseTraceHeader traceFileReader
    Printf.printfn "sizes: (ADDRINT: %d), (BOOL: %d), (THREADID: %d)" addrint_size bool_size threadid_size
    // let trace_length = getTraceLengthX8664 traceFileReader
    // Printf.printfn "number of serialized instructions: %d" trace_length
    let trace = deserializeTraceX8664 traceFileReader
    printTraceX8664 trace
    1
 // printfn "%A" argv
 // 0 // return an integer exit code
