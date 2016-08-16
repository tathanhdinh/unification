type Flag =
  | ZF
  | CF

type ControlFlow =
  | Continuous
  | StaticFlow of Flag * bool
  | DynamicFlow of Flag * bool

type LowVmInstruction =
  { bitAddress : uint32;
    data : uint32;
    prefixValue : byte;
    packedOperandSize : byte;
    suffixSize : byte }

[<StructAttribute>]
type RopEntry(address : uint32, length : byte, flag : byte, nextAddress : uint32, transitionAddress : uint32) =
  member this.Address = address
  member this.Length = length
  member this.Flag = flag
  member this.NextAddress = nextAddress
  member this.TransitionAddress = transitionAddress
  override this.ToString() =
    Printf.sprintf "[0x%x, %d, %d, 0x%x, 0x%x]" this.Address this.Length this.Flag this.NextAddress this.TransitionAddress

let parseRopEntries (binReader : System.IO.BinaryReader) (asmReader : AsmResolver.WindowsAssembly) =
  let imgBase = asmReader.NtHeaders.OptionalHeader.ImageBase
  let beginOffset = asmReader.RvaToFileOffset <| int64 (0x404309UL - imgBase)
  let endOffset = asmReader.RvaToFileOffset <| int64 (0x4046b1UL - imgBase)
  // let mutable ropEntries = []
  let ropEntries = new ResizeArray<_>()
  let mutable entryOffset = beginOffset
  while entryOffset < endOffset do
    binReader.BaseStream.Seek(entryOffset, System.IO.SeekOrigin.Begin) |> ignore
    let ropAddr = binReader.ReadUInt32()
    let ropLen = binReader.ReadByte()
    let ropFlag = binReader.ReadByte()
    let ropNextAddr = binReader.ReadUInt32()
    let ropTransAddr = (uint32 imgBase) + (uint32 <| asmReader.FileOffsetToRva(entryOffset + 0xaL))
    let entry = RopEntry(ropAddr, ropLen, ropFlag, ropNextAddr, ropTransAddr)
    // ropEntries <- entry :: ropEntries
    ropEntries.Add entry
    entryOffset <- entryOffset + (int64 ropLen)
  Seq.toList ropEntries
  // List.rev ropEntries
// begin for writeup
let calculateNewReturnAddress (retAddr:uint32) (retTable:byte[]) =
  let mutable entryOffset = 0
  while retAddr <> System.BitConverter.ToUInt32(retTable, entryOffset) do
    let entryLength = retTable.[entryOffset + 4]
    entryOffset <- entryOffset + (int entryLength)
  uint32 (entryOffset + 10)

// end for writeup

// let parseRopTable (binReader : System.IO.BinaryReader) (asmReader : AsmResolver.WindowsAssembly) =
//   let imgBase = asmReader.NtHeaders.OptionalHeader.ImageBase
//   let beginOffset = asmReader.RvaToFileOffset <| int64 (0x404309UL - imgBase)
//   let endOffset = asmReader.RvaToFileOffset <| int64 (0x4046b1UL - imgBase)
//   let ropAddrs = ref List.empty
//   let current_rop_offset = ref beginOffset
//   while !current_rop_offset < endOffset do
//     binReader.BaseStream.Seek(!current_rop_offset, System.IO.SeekOrigin.Begin) |> ignore
//     let current_rop_addr = binReader.ReadUInt32()
//     let current_rop_len = binReader.ReadByte()
//     let current_rop_flag = binReader.ReadByte()
//     let next_rop_addr = binReader.ReadUInt32()
//     ropAddrs := !ropAddrs @ [ current_rop_addr; next_rop_addr ]
//     current_rop_offset := !current_rop_offset + (int64 current_rop_len)
//   List.sort !ropAddrs |> List.distinct

let parse_rop_dynamic_control_flow (binReader : System.IO.BinaryReader) (asmReader : AsmResolver.WindowsAssembly) =
  let imgBase = asmReader.NtHeaders.OptionalHeader.ImageBase
  let begin_offset = asmReader.RvaToFileOffset(int64 (0x404309UL - imgBase))
  let end_offset = asmReader.RvaToFileOffset(int64 (0x4046b1UL - imgBase))
  let rop_cf = ref List.empty
  let current_rop_offset = ref begin_offset
  while !current_rop_offset < end_offset do
    binReader.BaseStream.Seek(!current_rop_offset, System.IO.SeekOrigin.Begin) |> ignore
    let current_rop_addr = binReader.ReadUInt32()
    let current_rop_len = binReader.ReadByte()
    let current_rop_flag = binReader.ReadByte()
    let next_rop_addr = binReader.ReadUInt32()
    rop_cf := (current_rop_addr, next_rop_addr) :: !rop_cf
    current_rop_offset := !current_rop_offset + (int64 current_rop_len)
  List.rev !rop_cf

let extractBounds (binReader : System.IO.BinaryReader) (asmReader : AsmResolver.WindowsAssembly) =
  let imgBase = asmReader.NtHeaders.OptionalHeader.ImageBase
  let beginOffset = asmReader.RvaToFileOffset(int64 (0x40406dUL - imgBase))
  let endOffset = asmReader.RvaToFileOffset(int64 (0x40424dUL - imgBase))
  let intervalTable = new ResizeArray<_>()
  let mutable currentEntryOffset = beginOffset
  binReader.BaseStream.Seek(currentEntryOffset, System.IO.SeekOrigin.Begin) |> ignore
  while currentEntryOffset < endOffset do
    let aBound = binReader.ReadUInt32()
    intervalTable.Add aBound
    currentEntryOffset <- currentEntryOffset + (int64 4)
  Seq.toList intervalTable

let computeOpcodeIntervalMap ropAddresses boundTable =
  let loBounds, hiBounds = List.foldBack (fun addr (los, his) -> addr :: his, los) boundTable ([], [])
  let intervals = List.zip loBounds hiBounds
  // let mutable rangeMap = Map.empty
  let intervalMap = new System.Collections.Generic.Dictionary<_, _>()
  List.iter (fun addr ->
    match List.tryFind (fun interval -> (fst interval <= addr && addr <= snd interval)) intervals with
    | Some range -> intervalMap.Add(addr, range)
    | None -> ()) ropAddresses
  intervalMap

// begin for writeup
let calculateOpcodeInterval retAddr intervalTable =
  let loBounds, hiBounds = List.foldBack (fun addr (los, his) -> addr :: his, los) intervalTable ([], [])
  let intervals = List.zip loBounds hiBounds
  List.find (fun interval -> (fst interval <= retAddr && retAddr <= snd interval)) intervals
// end for writeup

let compute_opcode_intervals rop_addresses bound_table =
  let lo_bounds, hi_bounds = List.foldBack (fun addr (los, his) -> addr :: his, los) bound_table ([], [])
  let ranges = List.zip lo_bounds hi_bounds
  let opcode_ranges = ref List.empty
  List.iter (fun addr ->
    match List.tryFind (fun range -> (fst range <= addr && addr <= snd range)) ranges with
    | Some range -> opcode_ranges := range :: !opcode_ranges
    | None -> ()) rop_addresses
  List.distinct !opcode_ranges |> List.rev

let compute_cf_entrypoint cf = 0x402058

let compute_control_flow (rop_table : RopEntry list) =
  let all_rops = ref List.empty
  List.iter (fun (entry : RopEntry) -> all_rops := entry.Address :: entry.NextAddress :: !all_rops) rop_table
  all_rops := List.sort !all_rops |> List.distinct
  let static_flow =
    List.zip (List.rev !all_rops
              |> List.tail
              |> List.rev) (List.tail !all_rops)

  let static_edges = ref List.empty
  List.iter (fun (from_rop, to_rop) ->
    //    if (from_rop = 0x402673ul || to_rop = 0x402673ul) then ()
    //    else
    match List.tryFind (fun (entry : RopEntry) -> entry.Address = to_rop) rop_table with
    | Some entry ->
      if (entry.Flag = 19uy) then ()
      else if (entry.Flag = 16uy) then
        static_edges
        := QuickGraph.TaggedEdge<uint32, ControlFlow>(from_rop, to_rop, StaticFlow(Flag.CF, false)) :: !static_edges
      else if (entry.Flag = 17uy) then
        static_edges
        := QuickGraph.TaggedEdge<uint32, ControlFlow>(from_rop, to_rop, StaticFlow(Flag.CF, true)) :: !static_edges
      else if (entry.Flag = 28uy) then
        static_edges
        := QuickGraph.TaggedEdge<uint32, ControlFlow>(from_rop, to_rop, StaticFlow(Flag.ZF, false)) :: !static_edges
      else if (entry.Flag = 29uy) then
        static_edges
        := QuickGraph.TaggedEdge<uint32, ControlFlow>(from_rop, to_rop, StaticFlow(Flag.ZF, true)) :: !static_edges
      else ()
    | None -> static_edges := QuickGraph.TaggedEdge<uint32, ControlFlow>(from_rop, to_rop, Continuous) :: !static_edges)
    static_flow
  let dynamic_edges = ref List.empty
  List.iter (fun (from_rop, to_rop) ->
    //    if (from_rop = 0x402673ul || to_rop = 0x402673ul) then ()
    //    else
    match List.tryFind (fun (entry : RopEntry) -> entry.Address = to_rop) rop_table with
    | Some entry ->
      if (entry.Flag = 19uy) then
        dynamic_edges
        := QuickGraph.TaggedEdge<uint32, ControlFlow>(from_rop, entry.NextAddress, Continuous) :: !dynamic_edges
      else if (entry.Flag = 16uy) then
        dynamic_edges
        := QuickGraph.TaggedEdge<uint32, ControlFlow>(from_rop, entry.NextAddress, DynamicFlow(Flag.CF, false))
           :: !dynamic_edges
      else if (entry.Flag = 17uy) then
        dynamic_edges
        := QuickGraph.TaggedEdge<uint32, ControlFlow>(from_rop, entry.NextAddress, DynamicFlow(Flag.CF, true))
           :: !dynamic_edges
      else if (entry.Flag = 28uy) then
        dynamic_edges
        := QuickGraph.TaggedEdge<uint32, ControlFlow>(from_rop, entry.NextAddress, DynamicFlow(Flag.ZF, false))
           :: !dynamic_edges
      else if (entry.Flag = 29uy) then
        dynamic_edges
        := QuickGraph.TaggedEdge<uint32, ControlFlow>(from_rop, entry.NextAddress, DynamicFlow(Flag.ZF, true))
           :: !dynamic_edges
      else ()
    | None -> ()) static_flow
  let not_relate_to_exit =
    fun (edge : QuickGraph.TaggedEdge<uint32, ControlFlow>) -> edge.Source <> 0x402673ul && edge.Target <> 0x402673ul
  let cfg =
    QuickGraph.GraphExtensions.ToAdjacencyGraph
      ((List.filter not_relate_to_exit !static_edges) @ (List.filter not_relate_to_exit !dynamic_edges))
  cfg

//  let dynamic_flow = ref List.empty
//  List.iter (fun (from_rop, to_rop) ->
//    match List.tryFind (fun (entry:RopEntry) -> entry.Address = to_rop) rop_table with
//      | Some entry -> dynamic_flow := (from_rop, entry.NextAddress) :: !dynamic_flow
//      | None -> ()
//  ) static_flow
//  let prunned_static_flow =
//    List.filter (fun (from_rop, to_rop) ->
//      match List.tryFind (fun (entry:RopEntry) -> entry.Address = to_rop) rop_table with
//        | Some entry -> entry.Flag <> 19uy
//        | None -> true
//    ) static_flow
//  let trim_exit_point = fun (from_rop, to_rop) -> from_rop <> 0x402673ul && to_rop <> 0x402673ul
//  let trimmed_static_flow = List.filter trim_exit_point prunned_static_flow
//  let trimmed_dynamic_flow = List.filter trim_exit_point !dynamic_flow
//  let static_edges = List.map (fun (from_rop, to_rop) -> QuickGraph.TaggedEdge<uint32, ControlFlow>(from_rop, to_rop, StaticFlow)) trimmed_static_flow
//  let dynamic_edges = List.map (fun (from_rop, to_rop) -> QuickGraph.TaggedEdge<uint32, ControlFlow>(from_rop, to_rop, DynamicFlow)) trimmed_dynamic_flow
//  let cfg = QuickGraph.GraphExtensions.ToAdjacencyGraph(static_edges @ dynamic_edges)
//  cfg
type FileDotEngine() =
  interface QuickGraph.Graphviz.IDotEngine with
    member this.Run(image_type, dot_string, output_filename) =
      System.IO.File.WriteAllText(output_filename, dot_string)
      dot_string

let draw_control_flow (cfg : QuickGraph.AdjacencyGraph<uint32, QuickGraph.TaggedEdge<uint32, ControlFlow>>)
    (rop_table : RopEntry list) output_filename =
  let graphviz = QuickGraph.Graphviz.GraphvizAlgorithm<uint32, QuickGraph.TaggedEdge<uint32, ControlFlow>>(cfg)
  graphviz.FormatVertex.Add(fun args ->
    args.VertexFormatter.Label <- if (args.Vertex = 0x4023d4ul) then Printf.sprintf "0x%x (Yes!)" args.Vertex
                                  else if (args.Vertex = 0x40266eul) then Printf.sprintf "0x%x (Nop)" args.Vertex
                                  else Printf.sprintf "0x%x" args.Vertex
    args.VertexFormatter.Shape <- QuickGraph.Graphviz.Dot.GraphvizVertexShape.Box
    args.VertexFormatter.Style <- QuickGraph.Graphviz.Dot.GraphvizVertexStyle.Rounded)
  //    if (args.Vertex = 0x402048ul)
  //    then args.VertexFormatter.FillColor <- QuickGraph.Graphviz.Dot.GraphvizColor.LightYellow
  //    else ()
  //    if (args.Vertex = 0x4023d4ul)
  //    then args.VertexFormatter.BottomLabel <- @"Yes!"
  //    else if (args.Vertex = 0x40266eul)
  //    then args.VertexFormatter.BottomLabel <- @"Nop"
  //    else ()
  graphviz.FormatEdge.Add(fun args ->
    //    args.EdgeFormatter.Label.Value <-
    //      match args.Edge.Tag with
    //        | StaticFlow -> "static"
    //        | DynamicFlow ->"dynamic"
    args.EdgeFormatter.Label.Value <- match args.Edge.Tag with
                                      | StaticFlow(Flag.CF, false) -> "CF != 0"
                                      | StaticFlow(Flag.CF, true) -> "CF != 1"
                                      | StaticFlow(Flag.ZF, false) -> "ZF != 0"
                                      | StaticFlow(Flag.ZF, true) -> "ZF != 1"
                                      | DynamicFlow(Flag.CF, false) -> "CF = 0"
                                      | DynamicFlow(Flag.CF, true) -> "CF = 1"
                                      | DynamicFlow(Flag.ZF, false) -> "ZF = 0"
                                      | DynamicFlow(Flag.ZF, true) -> "ZF = 1"
                                      | Continuous -> ""
    //      let target_rop_entry = List.tryFind (fun (entry:RopEntry) -> entry.Address = args.Edge.Target) rop_table
    //      match target_rop_entry with
    //        | Some rop_entry ->
    //          match args.Edge.Tag with
    //          | StaticFlow ->
    //            if (rop_entry.Flag = 16uy) then @"CF != 0"
    //            else if (rop_entry.Flag = 17uy) then @"CF != 1"
    //            else if (rop_entry.Flag = 28uy) then @"ZF != 0"
    //            else if (rop_entry.Flag = 29uy) then @"ZF != 1"
    //            else Printf.sprintf "flag: %d" rop_entry.Flag
    //          | DynamicFlow ->
    //            if (rop_entry.Flag = 16uy) then @"CF = 0"
    //            else if (rop_entry.Flag = 17uy) then @"CF = 1"
    //            else if (rop_entry.Flag = 28uy) then @"ZF = 0"
    //            else if (rop_entry.Flag = 29uy) then @"ZF = 1"
    //            else Printf.sprintf "flag: %d" rop_entry.Flag
    //        | None _ -> @""
    args.EdgeFormatter.Style <- match args.Edge.Tag with
                                | Continuous -> QuickGraph.Graphviz.Dot.GraphvizEdgeStyle.Solid
                                | _ -> QuickGraph.Graphviz.Dot.GraphvizEdgeStyle.Dashed)
  //    args.EdgeFormatter.Style <-
  //      match args.Edge.Tag with
  //        | StaticFlow ->
  graphviz.Generate(new FileDotEngine(), output_filename) |> ignore

let extract_low_layer_vm_data (bin_reader : System.IO.BinaryReader) (asm_reader : AsmResolver.WindowsAssembly) =
  let image_base = asm_reader.NtHeaders.OptionalHeader.ImageBase
  let begin_offset = asm_reader.RvaToFileOffset(int64 (0x40268BUL - image_base))
  let end_offset = asm_reader.RvaToFileOffset(int64 (0x4026A7UL - image_base))
  bin_reader.BaseStream.Seek(begin_offset, System.IO.SeekOrigin.Begin) |> ignore
  let vm_data = ref List.empty
  for i = 0 to 6 do
    let entry = bin_reader.ReadUInt32()
    vm_data := entry :: !vm_data
  List.rev !vm_data

let read_vm_data (bin_reader : System.IO.BinaryReader) (base_address : uint32) (bit_offset : uint32) =
  let byte_offset = bit_offset / 8ul
  bin_reader.BaseStream.Seek(int64 (base_address + byte_offset), System.IO.SeekOrigin.Begin) |> ignore
  let big_endian_array =
    bin_reader.ReadUInt32()
    |> System.BitConverter.GetBytes
    |> Array.rev

  let big_endian_data = System.BitConverter.ToUInt32(big_endian_array, 0)
  big_endian_data <<< (int32 bit_offset % 8)

let decode_instruction (bin_reader : System.IO.BinaryReader) (base_address : uint32) (ins_bit_offset : uint32) =
  let ins_data_with_prefix = read_vm_data bin_reader base_address ins_bit_offset
  let ins_data = ins_data_with_prefix <<< 0x2
  if (ins_data_with_prefix &&& 0xc0000000ul = 0ul) then // prefix 00
    { bitAddress = ins_bit_offset
      data = ins_data
      prefixValue = 0uy
      packedOperandSize = 16uy
      suffixSize = 3uy }
  else if (ins_data_with_prefix &&& 0x80000000ul = 0ul) then // prefix 01
    { bitAddress = ins_bit_offset
      data = ins_data
      prefixValue = 1uy
      packedOperandSize = 6uy
      suffixSize = 2uy }
  else if (ins_data_with_prefix &&& 0x40000000ul = 0ul) then // prefix 10
    { bitAddress = ins_bit_offset
      data = ins_data
      prefixValue = 2uy
      packedOperandSize = 3uy
      suffixSize = 1uy }
  else // prefix 11
    { bitAddress = ins_bit_offset
      data = ins_data
      prefixValue = 3uy
      packedOperandSize = 6uy
      suffixSize = 3uy }

let rec disassemble (bin_reader : System.IO.BinaryReader) (base_address : uint32) (current_bit_addr : uint32)
        decoded_inss =
  let new_ins = decode_instruction bin_reader base_address current_bit_addr
  if List.exists (fun (ins : LowVmInstruction) -> ins.bitAddress = new_ins.bitAddress) decoded_inss then decoded_inss
  else
    let new_decoded_inss = new_ins :: decoded_inss
    match new_ins with
    | { bitAddress = _; data = _; prefixValue = 0uy; packedOperandSize = 16uy; suffixSize = 3uy } ->
      let jump_bit_addr = new_ins.data >>> 16
      let next_ins_bit_addr = current_bit_addr + 0x15ul
      if (new_ins.data &&& 0xe000ul = 0ul) then // 00|esi:16|000
        let next_decoded_inss = disassemble bin_reader base_address next_ins_bit_addr new_decoded_inss
        disassemble bin_reader base_address jump_bit_addr next_decoded_inss
      else if (new_ins.data &&& 0xc000ul = 0ul) then // 00|esi:16|001
        let next_decoded_inss = disassemble bin_reader base_address next_ins_bit_addr new_decoded_inss
        disassemble bin_reader base_address jump_bit_addr next_decoded_inss
      else if (new_ins.data &&& 0xa000ul = 0ul) then // 00|esi:16|010
        disassemble bin_reader base_address jump_bit_addr new_decoded_inss
      else if (new_ins.data &&& 0x8000ul = 0ul) then // 00|esi:16|011
        disassemble bin_reader base_address (current_bit_addr + 0x15ul) new_decoded_inss
      else if (new_ins.data &&& 0x6000ul = 0ul) then // 00|esi:16|100
        disassemble bin_reader base_address (current_bit_addr + 0x15ul) new_decoded_inss
      else // 00|esi:16|(101,110,111)
        new_decoded_inss
    | { bitAddress = _; data = _; prefixValue = 1uy; packedOperandSize = 6uy; suffixSize = 2uy } ->
      if (new_ins.data &&& 0x3000000ul = 0ul) then // 01|esi:3|edi:3|00
        let next_ins_bit_addr = current_bit_addr + 0xaul
        disassemble bin_reader base_address next_ins_bit_addr new_decoded_inss
      else if (new_ins.data &&& 0x2000000ul = 0ul) then // 01|esi:3|edi:3|01
        let next_instruction_bit_address = current_bit_addr + 0xaul + 0x20ul
        disassemble bin_reader base_address next_instruction_bit_address new_decoded_inss
      else // 01|edi:3|esi:3|(10,11)
        let next_instruction_bit_address = current_bit_addr + 0xaul + 0x10ul
        disassemble bin_reader base_address next_instruction_bit_address new_decoded_inss
    | { bitAddress = _; data = _; prefixValue = 2uy; packedOperandSize = 3uy; suffixSize = 1uy } ->
      let next_ins_bit_addr = current_bit_addr + 0x6ul
      disassemble bin_reader base_address next_ins_bit_addr new_decoded_inss
    | { bitAddress = _; data = _; prefixValue = 3uy; packedOperandSize = 6uy; suffixSize = 3uy } ->
      let next_ins_bit_addr = current_bit_addr + 0xbul
      disassemble bin_reader base_address next_ins_bit_addr new_decoded_inss
    | _ ->
      failwith
      <| Printf.sprintf "unknown instruction, prefix_value = %d, operand_size = %d, suffix size = %d"
           new_ins.prefixValue new_ins.packedOperandSize new_ins.suffixSize

let disassemble_low_vms (bin_reader : System.IO.BinaryReader) (asm_reader : AsmResolver.WindowsAssembly) =
  let image_base = asm_reader.NtHeaders.OptionalHeader.ImageBase
  List.map (fun vm_address ->
    let vm_file_offset = asm_reader.RvaToFileOffset(int64 (uint64 vm_address - image_base))
    List.sortBy (fun ins -> ins.bitAddress) <| disassemble bin_reader (uint32 vm_file_offset) 0ul [])
    [ 0x403c32ul; 0x40365bul; 0x403056ul; 0x403598ul; 0x40312dul; 0x403d88ul; 0x403000ul ]

let decompile_instruction (ins : LowVmInstruction) (bin_reader : System.IO.BinaryReader) (base_address : uint32, crtn_idx : byte) =
  match ins with
  | { bitAddress = _; data = _; prefixValue = 0uy; packedOperandSize = 16uy; suffixSize = 3uy } ->
    let operand = ins.data >>> 16
    if (ins.data &&& 0xe000ul = 0ul) then // 00|esi:16|000
      Printf.sprintf "if (0x403654[%d] == 0x01) then goto 0x%03x" crtn_idx operand
    else if (ins.data &&& 0xc000ul = 0ul) then // 00|esi:16|001
      Printf.sprintf "if (0x403654[%d] != 0x01) then goto 0x%03x" crtn_idx operand
    else if (ins.data &&& 0xa000ul = 0ul) then // 00|esi:16|010
      Printf.sprintf "goto 0x%03x" operand
    else if (ins.data &&& 0x8000ul = 0ul) then // 00|esi:16|011
      Printf.sprintf "if (0x403732[%d] != 0xff) then goto 0x%03x else 0x403732[%d] = 0x%02x" operand ins.bitAddress operand crtn_idx
    else if (ins.data &&& 0x6000ul = 0ul) then // 00|esi:16|100
      Printf.sprintf "if (0x403732[%d] != 0x%02x) then goto 0x%03x else 0x403732[%d] = 0xff" operand crtn_idx ins.bitAddress operand
    else Printf.sprintf "check_password(0x403832)"
  | { bitAddress = _; data = _; prefixValue = 1uy; packedOperandSize = 6uy; suffixSize = 2uy } ->
    let operand0 = ins.data >>> 29
    let operand1 = (ins.data >>> 26) &&& 7ul
    if (ins.data &&& 0x3000000ul = 0ul) then // 01|esi:3|edi:3|00
      Printf.sprintf "0x403ca8[%d][%d] = 0x403ca8[%d][%d]" crtn_idx operand0 crtn_idx operand1
    else if (ins.data &&& 0x2000000ul = 0ul) then // 01|esi:3|edi:3|01
      let local_operand0 = (read_vm_data bin_reader base_address (ins.bitAddress + 10ul)) &&& 0xffff0000ul
      let local_operand1 = (read_vm_data bin_reader base_address (ins.bitAddress + 10ul + 16ul)) >>> 16
      Printf.sprintf "0x403ca8[%d][%d] = 0x%08x" crtn_idx operand0 (local_operand0 ||| local_operand1)
    else if (ins.data &&& 0x1000000ul = 0ul) then // 01|esi:3|edi:3|10
      let operand1 = (ins.data >>> 26) &&& 7ul
      let local_operand = (read_vm_data bin_reader base_address (ins.bitAddress + 10ul)) >>> 16
      Printf.sprintf "if (0x403732[%d] == 0x%02x) then password[%d] = 0x403ca8[%d][%d] else goto 0x%03x" local_operand crtn_idx local_operand crtn_idx operand1 ins.bitAddress
    else // 01|esi:3|edi:3|11
      let operand0 = ins.data >>> 29
      let local_operand = (read_vm_data bin_reader base_address (ins.bitAddress + 10ul)) >>> 16
      Printf.sprintf "if (0x403732[%d] == 0x%02x) then 0x403ca8[%d][%d] = password[%d] else goto 0x%03x" local_operand crtn_idx crtn_idx operand0 local_operand ins.bitAddress
  | { bitAddress = _; data = _; prefixValue = 2uy; packedOperandSize = 3uy; suffixSize = 1uy } ->
    let operand = ins.data >>> 29
    if (ins.data &&& 0x10000000ul = 0ul) then // 10|eax:3|0
      Printf.sprintf "0x403ca8[%d][%d] = reverse32(0x403ca8[%d][%d])" crtn_idx operand crtn_idx operand
    else // 10|eax:3|1
      Printf.sprintf "tmp_ecx = ++0x403832[%d][0]; 0x403832[%d][tmp_ecx] = 0x403ca8[%d][%d]" crtn_idx crtn_idx crtn_idx operand
  | { bitAddress = _; data = _; prefixValue = 3uy; packedOperandSize = 6uy; suffixSize = 3uy } ->
    let operand0 = ins.data >>> 29
    let operand1 = (ins.data >>> 26) &&& 7ul
    if (ins.data &&& 0x3800000ul = 0ul) then // 11|esi:3|edi:3|000
      Printf.sprintf "0x403ca8[%d][%d] += 0x403ca8[%d][%d]" crtn_idx operand0 crtn_idx operand1
    else if (ins.data &&& 0x3000000ul = 0ul) then // 11|esi:3|edi:3|001
      Printf.sprintf "0x403ca8[%d][%d] -= 0x403ca8[%d][%d]" crtn_idx operand0 crtn_idx operand1
    else if (ins.data &&& 0x2800000ul = 0ul) then // 11|esi:3|edi:3|010
//      Printf.sprintf "0x403ca8[crtn_idx][%d] =(0x403ca8[crtn_idx][%d] << 0x403ca8[crtn_idx][%d]) || (0x403ca8[crtn_idx][%d] >> (32 - 0x403ca8[crtn_idx][%d]))" operand0 operand0 operand1 operand0 operand1
      Printf.sprintf "0x403ca8[%d][%d] = rotl32(0x403ca8[%d][%d], 0x403ca8[%d][%d])" crtn_idx operand0 crtn_idx operand0 crtn_idx operand1
    else if (ins.data &&& 0x2000000ul = 0ul) then // 11|esi:3|edi:3|011
//      Printf.sprintf "0x403ca8[crtn_idx][%d] =(0x403ca8[crtn_idx][%d] >> 0x403ca8[crtn_idx][%d]) || (0x403ca8[crtn_idx][%d] << (32 - 0x403ca8[crtn_idx][%d]))" operand0 operand0 operand1 operand0 operand1
      Printf.sprintf "0x403ca8[%d][%d] = ror32(0x403ca8[%d][%d], 0x403ca8[%d][%d])" crtn_idx operand0 crtn_idx operand0 crtn_idx operand1
    else if (ins.data &&& 0x1800000ul = 0ul) then // 11|esi:3|edi:3|100
      Printf.sprintf "0x403ca8[%d][%d] = 0x403ca8[%d][%d] ^ 0x403ca8[%d][%d]" crtn_idx operand0 crtn_idx operand1 crtn_idx operand0
    else if (ins.data &&& 0x1000000ul = 0ul) then // 11|esi:3|edi:3|101
      Printf.sprintf "0x403654[%d] = (0x403ca8[%d][%d] == 0x403ca8[%d][%d])" crtn_idx crtn_idx operand0 crtn_idx operand1
    else // 11|esi:3|edi:3|(110,111)
      Printf.sprintf "if (%d < 0x403832[%d][0]) then 0x403ca8[%d][0] = 0x403832[%d][%d] else goto 0x%03x" operand1 operand0 crtn_idx operand0 (operand1 + 1ul) ins.bitAddress
  | _ -> Printf.sprintf "not decompiled yet"

let decompile_low_vm (bin_reader : System.IO.BinaryReader) (asm_reader : AsmResolver.WindowsAssembly) (vm_rva : uint32, crtn_idx : byte) =
  let image_base = asm_reader.NtHeaders.OptionalHeader.ImageBase
  let vm_file_offset = uint32 <| asm_reader.RvaToFileOffset(int64 (uint64 vm_rva - image_base))
  let vm_inss = List.sortBy (fun ins -> ins.bitAddress) <| disassemble bin_reader (uint32 vm_file_offset) 0ul []
  List.map (fun ins -> (ins, decompile_instruction ins bin_reader (vm_file_offset, crtn_idx))) vm_inss

let context = new Microsoft.Z3.Context()

let process0_on_password (passwd_expr:Microsoft.Z3.BitVecExpr) (added_value:uint32) =
  context.MkBVAdd(passwd_expr, context.MkBV(added_value, 32ul))

let run_process0 (password_expr:Microsoft.Z3.BitVecExpr) (added_value:uint32) (output:System.IO.StreamWriter) =
  Printf.fprintfn output "\n;; running process 0"
  let result = context.MkBVConst("proc0_result", 32ul)
  Printf.fprintfn output "(declare-fun %s () (_ BitVec 32))" <| result.ToString()
  Printf.fprintfn output "(assert %s)" <| context.MkEq(result, context.MkBVAdd(password_expr, context.MkBV(added_value, 32ul))).ToString()
  result

let run_process0_rev (password_expr:Microsoft.Z3.BitVecExpr) (added_value:uint32) (output:System.IO.StreamWriter) =
  Printf.fprintfn output "\n;; running process 0"
  let result = context.MkBVConst("proc0_result", 32ul)
  Printf.fprintfn output "(declare-fun %s () (_ BitVec 32))" <| result.ToString()
  Printf.fprintfn output "(assert %s)" <| context.MkEq(result, context.MkBVAdd(password_expr, context.MkBV(added_value, 32ul))).ToString()
  result

// process1_on_password passwd_after_proc0 0x6dc555e2ul 0x0000001ful 0x0000036dul
let process1_on_password (passwd_expr:Microsoft.Z3.BitVecExpr) (proc1_reg2:uint32) (proc1_reg3:uint32) (proc1_reg4:uint32) =
  let proc1_reg1_bvexpr = ref passwd_expr
  let proc1_reg2_bvexpr = context.MkBV(proc1_reg2, 32ul)
  for i in 1ul .. proc1_reg4 do
    proc1_reg1_bvexpr := context.MkBVXOR(!proc1_reg1_bvexpr, proc1_reg2_bvexpr)
    proc1_reg1_bvexpr := context.MkBVRotateLeft(proc1_reg3, !proc1_reg1_bvexpr)
  !proc1_reg1_bvexpr

let run_process1 (passwd_expr:Microsoft.Z3.BitVecExpr) (proc1_reg2:uint32) (proc1_reg3:uint32) (proc1_reg4:uint32) (output:System.IO.StreamWriter) =
  Printf.fprintfn output "\n;; running process 1"
  let current_passwd_expr = ref passwd_expr
  let proc1_reg2_bvexpr = context.MkBV(proc1_reg2, 32ul)
  for i in 1ul .. proc1_reg4 do
    let next_passwd_expr = context.MkBVConst(Printf.sprintf "proc1_result_%d" i, 32ul)
    Printf.fprintfn output "(declare-fun %s () (_ BitVec 32))" <| next_passwd_expr.ToString()
    Printf.fprintfn output "(assert %s)" <| context.MkEq(next_passwd_expr,
                                                         context.MkBVRotateLeft(proc1_reg3,
                                                                                context.MkBVXOR(!current_passwd_expr,
                                                                                                proc1_reg2_bvexpr))).ToString()
    current_passwd_expr := next_passwd_expr
  !current_passwd_expr

let run_process1_rev (passwd_expr:Microsoft.Z3.BitVecExpr) (proc1_reg2:uint32) (proc1_reg3:uint32) (proc1_reg4:uint32) (output:System.IO.StreamWriter) =
  Printf.fprintfn output "\n;; running process 1"
  let result = context.MkBVConst("proc1_result", 32ul)
  Printf.fprintfn output "(declare-fun %s () (_ BitVec 32))" <| result.ToString()
  let proc1_reg2_bvexpr = context.MkBV(proc1_reg2, 32ul)
  let rec generate_result loop_idx =
    if loop_idx = 1ul then
//      context.MkBVRotateLeft(proc1_reg3, context.MkBVXOR(result, proc1_reg2_bvexpr))
      Printf.sprintf "((_ rotate_left 31) (bvxor proc0_result #x6dc555e2))"
    else
//      context.MkBVRotateLeft(proc1_reg3, context.MkBVXOR(generate_result (loop_idx - 1ul), proc1_reg2_bvexpr))
      Printf.sprintf "((_ rotate_left 31) (bvxor %s #x6dc555e2))" <| generate_result (loop_idx - 1ul)
//  let result_bvexpr = generate_result proc1_reg4
  Printf.fprintfn output "(assert (= proc1_result %s))" <| generate_result proc1_reg4
  result

let process2_on_password (passwd_expr:Microsoft.Z3.BitVecExpr) (proc2_reg2:uint32) (proc2_reg3:uint32) (proc2_reg4:uint32) =
  let proc2_reg1_bvexpr = ref passwd_expr
  let proc2_reg2_bvexpr = context.MkBV(proc2_reg2, 32ul)
  for i in 1ul .. proc2_reg4 do
    proc2_reg1_bvexpr := context.MkBVSub(!proc2_reg1_bvexpr, proc2_reg2_bvexpr)
    proc2_reg1_bvexpr := context.MkBVRotateRight(proc2_reg3, !proc2_reg1_bvexpr)
  !proc2_reg1_bvexpr

let run_process2 (passwd_expr:Microsoft.Z3.BitVecExpr) (proc2_reg2:uint32) (proc2_reg3:uint32) (proc2_reg4:uint32) (output:System.IO.StreamWriter) =
  Printf.fprintfn output "\n;; running process 2"
  let current_passwd_expr = ref passwd_expr
  let proc2_reg2_bvexpr = context.MkBV(proc2_reg2, 32ul)
  for i in 1ul .. proc2_reg4 do
    let next_passwd_expr = context.MkBVConst(Printf.sprintf "proc2_result_%d" i, 32ul)
    Printf.fprintfn output "(declare-fun %s () (_ BitVec 32))" <| next_passwd_expr.ToString()
    Printf.fprintfn output "(assert %s)" <| context.MkEq(next_passwd_expr,
                                                         context.MkBVRotateRight(proc2_reg3,
                                                                                 context.MkBVSub(!current_passwd_expr,
                                                                                                 proc2_reg2_bvexpr))).ToString()
    current_passwd_expr := next_passwd_expr
  !current_passwd_expr

let run_process2_rev (passwd_expr:Microsoft.Z3.BitVecExpr) (proc2_reg2:uint32) (proc2_reg3:uint32) (proc2_reg4:uint32) (output:System.IO.StreamWriter) =
  Printf.fprintfn output "\n;; running process 2"
  let result = context.MkBVConst("proc2_result", 32ul)
  Printf.fprintfn output "(declare-fun %s () (_ BitVec 32))" <| result.ToString()
  let proc2_reg2_bvexpr = context.MkBV(proc2_reg2, 32ul)
  let rec generate_result loop_idx =
    if loop_idx = 1ul then
      Printf.sprintf "((_ rotate_right %d) (bvsub proc0_result #x%08x))" proc2_reg3 proc2_reg2
    else
      Printf.sprintf "((_ rotate_right %d) (bvsub %s #x%08x))" proc2_reg3 (generate_result (loop_idx - 1ul)) proc2_reg2
  Printf.fprintfn output "(assert (= proc2_result %s))" (generate_result proc2_reg4)
  result

let rev_concat_bv (bv0:Microsoft.Z3.BitVecExpr) (bv1:Microsoft.Z3.BitVecExpr) = context.MkConcat(bv1, bv0)

let fast_reverse_bv (input_bv:Microsoft.Z3.BitVecExpr) =
  let output_bv = ref input_bv
  output_bv := context.MkBVOR(context.MkBVLSHR(context.MkBVAND(!output_bv, context.MkBV(0xaaaaaaaaul, 32ul)), context.MkBV(1ul, 32ul)),
                              context.MkBVSHL(context.MkBVAND(!output_bv, context.MkBV(0x55555555ul, 32ul)), context.MkBV(1ul, 32ul)))
  output_bv := context.MkBVOR(context.MkBVLSHR(context.MkBVAND(!output_bv, context.MkBV(0xccccccccul, 32ul)), context.MkBV(2ul, 32ul)),
                              context.MkBVSHL(context.MkBVAND(!output_bv, context.MkBV(0x33333333ul, 32ul)), context.MkBV(2ul, 32ul)))
  output_bv := context.MkBVOR(context.MkBVLSHR(context.MkBVAND(!output_bv, context.MkBV(0xf0f0f0f0ul, 32ul)), context.MkBV(4ul, 32ul)),
                              context.MkBVSHL(context.MkBVAND(!output_bv, context.MkBV(0x0f0f0f0ful, 32ul)), context.MkBV(4ul, 32ul)))
  output_bv := context.MkBVOR(context.MkBVLSHR(context.MkBVAND(!output_bv, context.MkBV(0xff00ff00ul, 32ul)), context.MkBV(8ul, 32ul)),
                              context.MkBVSHL(context.MkBVAND(!output_bv, context.MkBV(0x00ff00fful, 32ul)), context.MkBV(8ul, 32ul)))
  output_bv := context.MkBVOR(context.MkBVLSHR(!output_bv, context.MkBV(16ul, 32ul)), context.MkBVSHL(!output_bv, context.MkBV(16ul, 32ul)))
  !output_bv

let reverse_bv_rev (output:System.IO.StreamWriter) =
  Printf.fprintfn output "\n;; reverse bit function"
  let step1 = Printf.sprintf "(bvor (bvlshr (bvand x #xaaaaaaaa) #x00000001) (bvshl (bvand x #x55555555) #x00000001))"
  let step2 = Printf.sprintf "(bvor (bvlshr (bvand %s #xcccccccc) #x00000002) (bvshl (bvand %s #x33333333) #x00000002))" step1 step1
  let step3 = Printf.sprintf "(bvor (bvlshr (bvand %s #xf0f0f0f0) #x00000004) (bvshl (bvand %s #x0f0f0f0f) #x00000004))" step2 step2
  let step4 = Printf.sprintf "(bvor (bvlshr (bvand %s #xff00ff00) #x00000008) (bvshl (bvand %s #x00ff00ff) #x00000008))" step3 step3
  let result = Printf.sprintf "(bvor (bvlshr %s #x00000010) (bvshl %s #x00000010))" step4 step4
  Printf.fprintfn output "(define-fun reverse_bv ((x (_ BitVec 32))) (_ BitVec 32)\n%s)" result

let process3_on_password (passwd_expr:Microsoft.Z3.BitVecExpr) (proc3_reg2:uint32) (proc3_reg4:uint32) =
  let proc3_reg1_bvexpr = ref passwd_expr
  let proc3_reg2_bvexpr = context.MkBV(proc3_reg2, 32ul)
  for i in 1ul .. proc3_reg4 do
    proc3_reg1_bvexpr := fast_reverse_bv !proc3_reg1_bvexpr
    proc3_reg1_bvexpr := context.MkBVXOR(!proc3_reg1_bvexpr, proc3_reg2_bvexpr)
    proc3_reg1_bvexpr := context.MkBVAdd(!proc3_reg1_bvexpr, proc3_reg2_bvexpr)
  !proc3_reg1_bvexpr

let run_process3 (passwd_expr:Microsoft.Z3.BitVecExpr) (proc3_reg2:uint32) (proc3_reg4:uint32) (output:System.IO.StreamWriter) =
  Printf.fprintfn output "\n;; running process 3"
  let proc3_reg1_bvexpr = ref passwd_expr
  let proc3_reg2_bvexpr = context.MkBV(proc3_reg2, 32ul)
  for i in 1ul .. proc3_reg4 do
    let proc3_reg1_next_bvexpr = context.MkBVConst(Printf.sprintf "proc3_result_%d" i, 32ul)
    Printf.fprintfn output "(declare-fun %s () (_ BitVec 32))" <| proc3_reg1_next_bvexpr.ToString()
    Printf.fprintfn output "(assert %s)" <| context.MkEq(proc3_reg1_next_bvexpr,
                                                         context.MkBVAdd(context.MkBVXOR(fast_reverse_bv !proc3_reg1_bvexpr,
                                                                                         proc3_reg2_bvexpr),
                                                                         proc3_reg2_bvexpr)).ToString()
    proc3_reg1_bvexpr := proc3_reg1_next_bvexpr
  !proc3_reg1_bvexpr

let run_process3_rev (passwd_expr:Microsoft.Z3.BitVecExpr) (proc3_reg2:uint32) (proc3_reg4:uint32) (output:System.IO.StreamWriter) =
  Printf.fprintfn output "\n;; running process 3"
  let result = context.MkBVConst("proc3_result", 32ul)
  Printf.fprintfn output "(declare-fun %s () (_ BitVec 32))" <| result.ToString()
  let rec generate_result loop_idx =
    if loop_idx = 1ul then
      Printf.sprintf "(bvadd (bvxor (reverse_bv %s) #x%08x) #x%08x)" (passwd_expr.ToString()) proc3_reg2 proc3_reg2
    else
      Printf.sprintf "(bvadd (bvxor (reverse_bv %s) #x%08x) #x%08x)" (generate_result (loop_idx - 1ul)) proc3_reg2 proc3_reg2
  Printf.fprintfn output "(assert (= proc3_result %s))" (generate_result proc3_reg4)
  result

let process4_on_password (proc1_share:Microsoft.Z3.BitVecExpr) (proc2_share:Microsoft.Z3.BitVecExpr) (proc4_reg3:uint32) =
  let proc4_reg1 = context.MkBVXOR(proc2_share, context.MkBVRotateLeft(proc4_reg3, proc1_share))
  proc4_reg1

let run_process4 (proc1_share:Microsoft.Z3.BitVecExpr) (proc2_share:Microsoft.Z3.BitVecExpr) (proc4_reg3:uint32) (output:System.IO.StreamWriter) =
  Printf.fprintfn output "\n;; running process 4"
  let result_expr = context.MkBVConst("proc4_result", 32ul)
  Printf.fprintfn output "(declare-fun %s () (_ BitVec 32))" <| result_expr.ToString()
  Printf.fprintfn output "(assert %s)" <| context.MkEq(result_expr,
                                                       context.MkBVXOR(proc2_share,
                                                                       context.MkBVRotateLeft(proc4_reg3,
                                                                                              proc1_share))).ToString()
  result_expr

let run_process4_rev (proc1_share:Microsoft.Z3.BitVecExpr) (proc2_share:Microsoft.Z3.BitVecExpr) (proc4_reg3:uint32) (output:System.IO.StreamWriter) =
  Printf.fprintfn output "\n;; running process 4"
  let result = context.MkBVConst("proc4_result", 32ul)
  Printf.fprintfn output "(declare-fun %s () (_ BitVec 32))" <| result.ToString()
  Printf.fprintfn output "(assert (= %s (bvxor %s ((_ rotate_left %d) %s))))"  (result.ToString()) (proc2_share.ToString()) proc4_reg3 (proc1_share.ToString())
  result

let process5_on_password (proc2_share:Microsoft.Z3.BitVecExpr) (proc3_share:Microsoft.Z3.BitVecExpr) =
  let proc5_reg2 = fast_reverse_bv proc3_share
  context.MkBVXOR(proc5_reg2, proc2_share)

let run_process5 (proc2_share:Microsoft.Z3.BitVecExpr) (proc3_share:Microsoft.Z3.BitVecExpr) (output:System.IO.StreamWriter) =
  Printf.fprintfn output "\n;; running process 5"
  let result_expr = context.MkBVConst("proc5_result", 32ul)
  Printf.fprintfn output "(declare-fun %s () (_ BitVec 32))" <| result_expr.ToString()
  Printf.fprintfn output "(assert %s)" <| context.MkEq(result_expr,
                                                       context.MkBVXOR(fast_reverse_bv proc3_share,
                                                                       proc2_share)).ToString()
  result_expr

let run_process5_rev (proc2_share:Microsoft.Z3.BitVecExpr) (proc3_share:Microsoft.Z3.BitVecExpr) (output:System.IO.StreamWriter) =
  Printf.fprintfn output "\n;; running process 5"
  let result = context.MkBVConst("proc5_result", 32ul)
  Printf.fprintfn output "(declare-fun %s () (_ BitVec 32))" <| result.ToString()
  Printf.fprintfn output "(assert (= %s (bvxor (reverse_bv %s) %s)))" (result.ToString()) (proc3_share.ToString()) (proc2_share.ToString())
  result

let process6_on_password (proc4_share:Microsoft.Z3.BitVecExpr) (proc5_share:Microsoft.Z3.BitVecExpr) (proc6_reg3:uint32) =
  let proc6_reg1 = ref (context.MkBVRotateLeft(proc6_reg3, proc4_share))
  proc6_reg1 := context.MkBVXOR(proc5_share, !proc6_reg1)
  fast_reverse_bv !proc6_reg1

let run_process6 (proc4_share:Microsoft.Z3.BitVecExpr) (proc5_share:Microsoft.Z3.BitVecExpr) (output:System.IO.StreamWriter) =
  Printf.fprintfn output "\n;; running process 6"
  let result_expr = context.MkBVConst("proc6_result", 32ul)
  Printf.fprintfn output "(declare-fun %s () (_ BitVec 32))" <| result_expr.ToString()
  Printf.fprintfn output "(assert %s)" <| context.MkEq(result_expr,
                                                       fast_reverse_bv <| context.MkBVXOR(proc5_share,
                                                                                          context.MkBVRotateLeft(0x17ul,
                                                                                                                 proc4_share))).ToString()
  result_expr

let run_process6_rev (proc4_share:Microsoft.Z3.BitVecExpr) (proc5_share:Microsoft.Z3.BitVecExpr) (output:System.IO.StreamWriter) =
  Printf.fprintfn output "\n;; running process 6"
  let result = context.MkBVConst("proc6_result", 32ul)
  Printf.fprintfn output "(declare-fun %s () (_ BitVec 32))" <| result.ToString()
  Printf.fprintfn output "(assert (= %s (reverse_bv (bvxor %s ((_ rotate_left 23) %s)))))" (result.ToString()) (proc5_share.ToString()) (proc4_share.ToString())
  result

let run_synthese_rev (proc1_share:Microsoft.Z3.BitVecExpr) (proc2_share:Microsoft.Z3.BitVecExpr) (proc3_share:Microsoft.Z3.BitVecExpr) (proc4_reg3:uint32) (output:System.IO.StreamWriter) =
  Printf.fprintfn output "\n;; running synthese process"
  let result = context.MkBVConst("proc6_result_rev", 32ul)
  Printf.fprintfn output "(declare-fun %s () (_ BitVec 32))" <| result.ToString()
  let proc1_synthese_str = (context.MkBVRotateLeft(proc4_reg3 + 0x17ul, proc1_share)).ToString()
  let proc3_synthese_str = Printf.sprintf "(reverse_bv %s)" <| proc3_share.ToString()
  let proc2_rotl17 = context.MkBVRotateLeft(0x17ul, proc2_share)
  let proc2_synthese_str = Printf.sprintf "(bvxor %s %s)" (proc2_share.ToString()) (proc2_rotl17.ToString())
  Printf.fprintfn output "(assert (= %s (bvxor (bvxor %s %s) %s)))" (result.ToString()) proc1_synthese_str proc2_synthese_str proc3_synthese_str
  result

let check_password0 (output_smt_file:string) =
  use file_stream = new System.IO.StreamWriter(output_smt_file)
  Printf.fprintfn file_stream ("(set-logic QF_BV)\n(set-info :smt-lib-version 2.0)\n")

  let password0 = context.MkBVConst("password0", 32ul)
  Printf.fprintfn file_stream "(declare-fun %s () (_ BitVec 32))" <| password0.ToString()

  let passwd_after_proc0 = context.MkBVConst("password_after_proc0", 32ul)
  Printf.fprintfn file_stream "(declare-fun %s () (_ BitVec 32))" <| passwd_after_proc0.ToString()

  let constraint0 = context.MkEq(passwd_after_proc0, process0_on_password password0 0x550342b8ul)

  let proc1_share = context.MkBVConst("proc1_share", 32ul)
  Printf.fprintfn file_stream "(declare-fun %s () (_ BitVec 32))" <| proc1_share.ToString()
  let constraint1 = context.MkEq(proc1_share, process1_on_password passwd_after_proc0 0x6dc555e2ul 0x0000001ful 0x0000036dul)

  let proc2_share = context.MkBVConst("proc2_share", 32ul)
  Printf.fprintfn file_stream "(declare-fun %s () (_ BitVec 32))" <| proc2_share.ToString()
  let constraint2 = context.MkEq(proc2_share, process2_on_password passwd_after_proc0 0xecf6d571ul 0x0000000eul 0x0000006eul)

  let proc3_share = context.MkBVConst("proc3_share", 32ul)
  Printf.fprintfn file_stream "(declare-fun %s () (_ BitVec 32))" <| proc3_share.ToString()
  let constraint3 = context.MkEq(proc3_share, process3_on_password passwd_after_proc0 0x8fd5c5bdul 0x00000028ul);

  let proc4_share = context.MkBVConst("proc4_share", 32ul)
  Printf.fprintfn file_stream "(declare-fun %s () (_ BitVec 32))" <| proc4_share.ToString()
  let constraint4 = context.MkEq(proc4_share, process4_on_password proc1_share proc2_share 0x00000000ul)

  let proc5_share = context.MkBVConst("proc5_share", 32ul)
  Printf.fprintfn file_stream "(declare-fun %s () (_ BitVec 32))" <| proc5_share.ToString()
  let constraint5 = context.MkEq(proc5_share, process5_on_password proc2_share proc3_share)

  let proc6_share = context.MkBVConst("proc6_share", 32ul)
  Printf.fprintfn file_stream "(declare-fun %s () (_ BitVec 32))\n" <| proc6_share.ToString()
  let constraint6 = context.MkEq(proc6_share, process6_on_password proc4_share proc5_share 0x00000017ul)

  let eq_constraint = context.MkEq(proc6_share, context.MkBV(0x73ae5f50ul, 32ul))

  let main_constraints = eq_constraint :: [ constraint0; constraint1; constraint2; constraint3; constraint4; constraint5; constraint6 ]

  let password_chars = ref []
  for i in 0ul .. 3ul do
    password_chars := context.MkExtract(i * 8ul + 7ul,  i * 8ul, password0) :: !password_chars
  let char_constraints = List.map (fun char -> context.MkAnd([| context.MkBVUGE(char, context.MkBV(0x20ul, 8ul));
                                                                context.MkBVULE(context.MkBV(0x7eul, 8ul), char) |])) !password_chars

  let all_constraints = List.rev <| main_constraints @ char_constraints

  List.iter (fun cond -> Printf.fprintfn file_stream "(assert %s)\n" <| cond.ToString()) all_constraints
  Printf.fprintfn file_stream "(check-sat)"
  file_stream.Close()
  Printf.printfn "save formula to %s" output_smt_file

  let solver = context.MkSolver("QF_BV")
  solver.Assert(Array.ofList all_constraints)

  Printf.printfn "start searching for password..."

  if (solver.Check() = Microsoft.Z3.Status.SATISFIABLE) then
    Printf.printfn "password[0..3] = "
  else
    Printf.printfn "cannot found password"

let processing_password0 (output_smt_file:string) =
  Printf.printfn "saving SMT formula to %s ..." output_smt_file

  use file_stream = new System.IO.StreamWriter(output_smt_file)
  Printf.fprintfn file_stream ("(set-logic QF_BV)\n(set-info :smt-lib-version 2.0)\n")

  Printf.fprintfn file_stream ";; we need to find out the value of this expression"
  let password0 = context.MkBVConst("password0", 32ul)
  Printf.fprintfn file_stream "(declare-fun %s () (_ BitVec 32))" <| password0.ToString()

  Printf.fprintfn file_stream "\n;; additional conditions on characters of password"
  let password_chars = ref []
  for i in 0ul .. 3ul do
    password_chars := context.MkExtract(i * 8ul + 7ul,  i * 8ul, password0) :: !password_chars
  let char_constraints = List.map (fun char -> context.MkAnd([| context.MkBVUGE(char, context.MkBV(0x21ul, 8ul));
                                                                context.MkBVULE(context.MkBV(0x7eul, 8ul), char) |])) !password_chars
  List.iter (fun cond -> Printf.fprintfn file_stream "(assert %s)" <| cond.ToString()) char_constraints

  let passwd_after_proc0 = run_process0 password0 0x550342b8ul file_stream
  let proc1_share        = run_process1 passwd_after_proc0 0x6dc555e2ul 0x0000001ful 0x0000036dul file_stream
  let proc2_share        = run_process2 passwd_after_proc0 0xecf6d571ul 0x0000000eul 0x0000006eul file_stream
  let proc3_share        = run_process3 passwd_after_proc0 0x8fd5c5bdul 0x00000028ul file_stream
  let proc4_share        = run_process4 proc1_share proc2_share 0x00000000ul file_stream
  let proc5_share        = run_process5 proc2_share proc3_share file_stream
  let proc6_share        = run_process6 proc4_share proc5_share file_stream

  Printf.fprintfn file_stream "\n;; final condition"
  let eq_constraint = context.MkEq(proc6_share, context.MkBV(0x73ae5f50ul, 32ul))
  Printf.fprintfn file_stream "(assert %s)" <| eq_constraint.ToString()

  Printf.fprintfn file_stream "\n;; now check satisfiability"
  Printf.fprintfn file_stream "(check-sat)\n(get-value (password0))"

  Printf.printfn "saved!!!"

  file_stream.Close()

let process_password (output_smt_file:string) =
  Printf.printfn "saving SMT formula to %s ..." output_smt_file

  use file_stream = new System.IO.StreamWriter(output_smt_file)
  Printf.fprintfn file_stream ("(set-logic QF_BV)\n(set-info :smt-lib-version 2.0)\n")

  Printf.fprintfn file_stream ";; we need to find out the value of this expression"
  let password0 = context.MkBVConst("password0", 32ul)
  Printf.fprintfn file_stream "(declare-fun %s () (_ BitVec 32))" <| password0.ToString()

  Printf.fprintfn file_stream "\n;; additional conditions on characters of password"
  let password_chars = ref []
  for i in 0ul .. 3ul do
    password_chars := context.MkExtract(i * 8ul + 7ul,  i * 8ul, password0) :: !password_chars
  let char_constraints = List.map (fun char -> context.MkAnd([| context.MkBVUGE(char, context.MkBV(0x21ul, 8ul));
                                                                context.MkBVULE(char, context.MkBV(0x7eul, 8ul)) |])) !password_chars
  List.iter (fun cond -> Printf.fprintfn file_stream "(assert %s)" <| cond.ToString()) char_constraints

  let passwd_after_proc0 = run_process0_rev password0 0x550342b8ul file_stream
  let proc1_share = run_process1_rev passwd_after_proc0 0x6dc555e2ul 0x0000001ful 0x0000036dul file_stream
  let proc2_share = run_process2_rev passwd_after_proc0 0xecf6d571ul 0x0000000eul 0x0000006eul file_stream
  reverse_bv_rev file_stream
  let proc3_share = run_process3_rev passwd_after_proc0 0x8fd5c5bdul 0x00000028ul file_stream
//  let proc4_share = run_process4_rev proc1_share proc2_share 0x00000000ul file_stream
//  let proc5_share = run_process5_rev proc2_share proc3_share file_stream
//  let proc6_share = run_process6_rev proc4_share proc5_share file_stream
  let result_synthese = run_synthese_rev proc1_share proc2_share proc3_share 0x00000000ul file_stream

  Printf.fprintfn file_stream "\n;; final condition"

//  let eq_constraint = context.MkEq(proc6_share, context.MkBV(0x73ae5f50ul, 32ul))
//  let eq_constraint = context.MkEq(proc1_share, context.MkBV(0xd9ef05abul, 32ul))
//  let eq_constraint = context.MkEq(passwd_after_proc0, context.MkBV(0xa262730bul, 32ul))
//  let eq_constraint = context.MkEq(proc2_share, context.MkBV(0x5c793783ul, 32ul))
//  let eq_constraint = context.MkEq(proc3_share, context.MkBV(0x2a918342ul, 32ul))
//  let eq_constraint = context.MkEq(proc4_share, context.MkBV(0x85963228ul, 32ul))
//  let eq_constraint = context.MkEq(proc5_share, context.MkBV(0x1eb8bed7ul, 32ul))
  let eq_constraint = context.MkEq(result_synthese, context.MkBV(0x0afa75ceul, 32ul))

  Printf.fprintfn file_stream "(assert %s)" <| eq_constraint.ToString()

  Printf.fprintfn file_stream "\n;; now check satisfiability"
//  Printf.fprintfn file_stream "(check-sat)\n(get-value (password0))"
//  Printf.fprintfn file_stream "(check-sat)\n(get-value (%s))" (proc1_share.ToString())
  Printf.fprintfn file_stream "(check-sat)\n(get-value (%s))" (password0.ToString())

//  Printf.fprintfn file_stream "\n;; convert to CNF"
//  Printf.fprintfn file_stream "(apply (then (! simplify :elim-and true) elim-term-ite (! tseitin-cnf :distributivity false)))"

  Printf.printfn "saved!!!"

  file_stream.Close()

let decrypt_f4xorwkfu binary_path =
  use bin_reader = new System.IO.BinaryReader(System.IO.File.OpenRead(binary_path))
  let bin_asm = AsmResolver.WindowsAssembly.FromFile(binary_path)
  //  let rop_addresses = parse_rop_table bin_reader bin_asm
  let bound_table = extractBounds bin_reader bin_asm
  //  let range_map     = compute_opcode_range_map rop_addresses bound_table
  //  let rop_cf        = parse_rop_dynamic_control_flow bin_reader bin_asm
  let rop_table = parseRopEntries bin_reader bin_asm

  let rop_addresses =
    List.map (fun (rop_entry : RopEntry) -> rop_entry.Address) rop_table
    |> List.sort
    |> List.distinct

  let range_map = computeOpcodeIntervalMap rop_addresses bound_table
  let low_vms = disassemble_low_vms bin_reader bin_asm
  //  List.iter (fun addr -> Printf.printfn "0x%x" addr) rop_addresses
  //  List.iter (fun addr -> Printf.printf "0x%x " addr) bound_table
  //  Printf.printfn "gadget map: entry point => range"
  //  Map.iter (fun addr range -> Printf.printfn "0x%x => [0x%x, 0x%x]" addr (fst range) (snd range)) range_map
  //  Map.iter (fun addr range -> Printf.printf "(0x%x, 0x%x), " (fst range) (snd range)) range_map
  //  let opcode_intervals = compute_opcode_intervals rop_addresses bound_table
  //  List.iter (fun interv -> Printf.printf "(0x%x, 0x%x), " (fst interv) (snd interv)) opcode_intervals
  //  List.iter (fun cf -> Printf.printfn "0x%x -> 0x%x" (fst cf) (snd cf)) rop_cf
  //  List.iter (fun entry ->
  //    Printf.printfn "[0x%x, %d, %d, 0x%x, 0x%x]" entry.address entry.length entry.flag entry.next_address entry.transition_address
  //  ) rop_table
  //  List.sortBy (fun (entry:RopEntry) -> entry.Address) rop_table |> List.iter (fun entry -> Printf.printfn "%s" <| entry.ToString())
  //  let cfg = compute_control_flow rop_table
  //  draw_control_flow cfg rop_table @"F4b_XOR_W4kfu.cfg"
  //  let vm_data = extract_low_layer_vm_data bin_reader bin_asm
  //  List.iter (fun entry -> Printf.printf "0x%x, " entry) vm_data
  let coroutine_idx = ref 0
  //  List.iter (fun vm_instructions ->
  //    Printf.printfn "=========== coroutine %d ===========" !coroutine_idx
  //    coroutine_idx := !coroutine_idx + 1
  //    List.iter (fun vm_ins -> Printf.printfn "0x%03x: %s;" vm_ins.bit_address <| mnemonic vm_ins) vm_instructions)
  //    low_vms
  let decompiled_vms =
    List.map (fun vm_rva -> decompile_low_vm bin_reader bin_asm vm_rva)
      [ (0x403c32ul, 0uy); (0x40365bul, 1uy); (0x403056ul, 2uy); (0x403598ul, 3uy); (0x40312dul, 4uy); (0x403d88ul, 5uy); (0x403000ul, 6uy) ]
  List.iter
    (fun decompiled_vm ->
    Printf.printfn "=========== coroutine %d ===========" !coroutine_idx
//    Printf.printfn "crtn_idx = %d;" !coroutine_idx
    coroutine_idx := !coroutine_idx + 1
    List.iter (fun (vm_ins, decompiled_str) -> Printf.printfn "0x%03x: %s;" vm_ins.bitAddress decompiled_str)
      decompiled_vm) decompiled_vms
  bin_reader.Close()

let printInfo () =
  let binPath = @"F4b_XOR_W4kfu.exe"
  use binReader = new System.IO.BinaryReader(System.IO.File.OpenRead(binPath))
  let binAsm = AsmResolver.WindowsAssembly.FromFile(binPath)
  let intervalTable = extractBounds binReader binAsm
  let ropTable = parseRopEntries binReader binAsm

  let ropAddrs =
    List.map (fun (ropEntry : RopEntry) -> ropEntry.Address) ropTable
    |> List.sort |> List.distinct

  let transAddrs =
    List.map (fun (ropEntry:RopEntry) -> ropEntry.TransitionAddress) ropTable
    |> List.sort |> List.distinct

  let mutable newRopAddrs =
     List.map (fun (ropEntry:RopEntry) -> ropEntry.NextAddress) ropTable
     |> List.sort |> List.distinct

  newRopAddrs <- Set.toList (Set.difference (Set.ofList newRopAddrs) (Set.ofList ropAddrs))

  // let gadgetMap = computeOpcodeIntervalMap ropAddrs intervalTable
  let gadgetMap = computeOpcodeIntervalMap newRopAddrs intervalTable
  for Operators.KeyValue(entryPoint, (loBound, hiBound)) in gadgetMap do
    Printf.printf "0x%x => [0x%x, 0x%x]; " entryPoint loBound hiBound
  // Seq.iter (fun addr (lo, hi) -> Printf.printf "0x%x => [0x%x, 0x%x]; " addr lo hi) gadgetMap

  // List.iter (fun ropAddr -> Printf.printf "0x%x; " ropAddr) ropAddrs
  // Printf.printfn "%u" <| List.length transAddrs
  // List.iter (fun addr -> Printf.printf "0x%x; " addr) transAddrs
  // List.iter (fun (entry:RopEntry) -> Printf.printf "%u; " entry.Flag) ropTable 

  // let range_map = computeOpcodeIntervalMap ropAddrs intervalTable
  // let low_vms = disassemble_low_vms binReader binAsm

[<EntryPoint>]
let main argv =
  try
//    decrypt_f4xorwkfu @"F4b_XOR_W4kfu.exe"
//    check_password0 "password0.smt2"
//    processing_password0 "password0.smt2"
    // process_password "password.smt2"
    printInfo ()
    0
  with ex ->
    Printf.printfn "%s" <| ex.ToString()
    1
