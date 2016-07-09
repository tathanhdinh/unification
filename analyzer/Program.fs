// Learn more about F# at http://fsharp.net
// See the 'F# Tutorial' project for more help.

type Instruction<'TAddress, 'TThreadID> = { address: 'TAddress;
                                            mnemonic_string: string;
                                            thread_id: 'TThreadID }

let get_trace_length_x86_64 (trace_file_reader:System.IO.BinaryReader) =
 let trace_length:uint64 ref = ref (uint64 0)
 while (trace_file_reader.BaseStream.Position <> trace_file_reader.BaseStream.Length) do
   let instruction_length = trace_file_reader.ReadUInt64 ()
   trace_file_reader.BaseStream.Seek(int64 instruction_length, System.IO.SeekOrigin.Current) |> ignore
   trace_length := !trace_length + (uint64 1)
 trace_length


[<EntryPoint>]
let main argv = 
 printfn "%A" argv
 0 // return an integer exit code

