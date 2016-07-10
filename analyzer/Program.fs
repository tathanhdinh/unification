// Learn more about F# at http://fsharp.net
// See the 'F# Tutorial' project for more help.

type Instruction<'TAddress, 'TThreadID> = { Address: 'TAddress;
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

[<EntryPoint>]
let main argv =
  if Array.length argv <> 1 then
    Printf.printfn "give a serialized trace file from the command line (e.g. analyzer trace_file)"
    0
  else
    use traceFileReader = new System.IO.BinaryReader(System.IO.File.OpenRead(argv.[0]))
    let (addrint_size, bool_size, threadid_size) = parseTraceHeader traceFileReader
    Printf.printfn "ADDRINT size: %d\nBOOL size: %d\nTHREADID size: %d" addrint_size bool_size threadid_size
    // let trace_length = getTraceLengthX8664 traceFileReader
    // Printf.printfn "number of serialized instructions: %d" trace_length
    1
 // printfn "%A" argv
 // 0 // return an integer exit code
