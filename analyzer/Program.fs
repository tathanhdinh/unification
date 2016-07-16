type Instruction<'TAddress> = { Address: 'TAddress;
                                NextAddress: 'TAddress;
                                Mnemonic: string;
                                ThreadId: uint32 }

type ResizeTrace<'TAddress> = ResizeArray<Instruction<'TAddress>>

type DynamicTrace<'TAddress> = ResizeArray<'TAddress>

type InstructionMap<'TAddress when 'TAddress : comparison> = Map<'TAddress, Instruction<'TAddress>>

type BasicBlock<'TAddress> = 'TAddress list

type SimpleCFG<'TAddress> = QuickGraph.BidirectionalGraph<'TAddress, QuickGraph.SEdge<'TAddress>>

type BasicBlockCFG<'TAddress> = QuickGraph.BidirectionalGraph<BasicBlock<'TAddress>, QuickGraph.SEdge<BasicBlock<'TAddress>>>

let parseTraceHeader (traceFileReader:System.IO.BinaryReader) =
  let addrintSize = traceFileReader.ReadByte ()
  let boolSize = traceFileReader.ReadByte ()
  let threadidSize = traceFileReader.ReadByte ()
  (addrintSize, boolSize, threadidSize)

(*=====================================================================================================================*)

let getTraceLength<'TAddress when 'TAddress : unmanaged> (traceFileReader:System.IO.BinaryReader) =
  match typeof<'TAddress> with
    | t when t = typeof<uint32> ->
      let mutable traceLength = (uint32 0)
      while (traceFileReader.BaseStream.Position <> traceFileReader.BaseStream.Length) do
        let instruction_length = traceFileReader.ReadUInt32 ()
        traceFileReader.BaseStream.Seek (int64 instruction_length, System.IO.SeekOrigin.Current) |> ignore
        traceLength <- traceLength + (uint32 1)
      unbox<'TAddress> traceLength
    | t when t = typeof<uint64> ->
      let mutable traceLength = (uint64 0)
      while (traceFileReader.BaseStream.Position <> traceFileReader.BaseStream.Length) do
        let insLength = traceFileReader.ReadUInt64 ()
        traceFileReader.BaseStream.Seek (int64 insLength, System.IO.SeekOrigin.Current) |> ignore
        traceLength <- traceLength + (uint64 1)
      unbox<'TAddress> traceLength
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
  let opcodeSize =
    match typeof<'TAddress> with
      | t when t = typeof<uint32> -> int (traceFileReader.ReadUInt32 ())
      | t when t = typeof<uint64> -> int (traceFileReader.ReadUInt64 ())
      | _ -> failwith "unknown type parameter"
  let opcodeBuffer = traceFileReader.ReadBytes opcodeSize
  opcodeBuffer

let deserializeOpcodeX8664 (traceFileReader:System.IO.BinaryReader) =
  let opcode_size = traceFileReader.ReadUInt64 ()
  let opcode_buffer = traceFileReader.ReadBytes (int opcode_size)
  opcode_buffer
  // (opcode_size, opcode_buffer)

(*=====================================================================================================================*)

let deserializeMnemonic<'TAddress when 'TAddress : unmanaged> (traceFileReader:System.IO.BinaryReader) =
  let mnemonicLength =
    match typeof<'TAddress> with
      | t when t = typeof<uint32> -> int (traceFileReader.ReadUInt32 ())
      | t when t = typeof<uint64> -> int (traceFileReader.ReadUInt64 ())
      | _ -> failwith "unknown type parameter"
  let mnemonicStr = traceFileReader.ReadBytes mnemonicLength
  System.Text.Encoding.ASCII.GetString mnemonicStr

let deserializeMnemonicX8664 (traceFileReader:System.IO.BinaryReader) =
  let mnemonic_len = traceFileReader.ReadUInt64 ()
  let mnemonic_str = traceFileReader.ReadBytes (int mnemonic_len)
  System.Text.Encoding.ASCII.GetString mnemonic_str

(*=====================================================================================================================*)

let deserializeRegMap<'TAddress> (traceFileReader:System.IO.BinaryReader) =
  let regMapLength =
    match typeof<'TAddress> with
      | t when t = typeof<uint32> -> int (traceFileReader.ReadUInt32 ())
      | t when t = typeof<uint64> -> int (traceFileReader.ReadUInt64 ())
      | _ -> failwith "unknown type parameter"
  let regMapBuffer = traceFileReader.ReadBytes regMapLength
  regMapBuffer

let deserializeRegMapX8664 (traceFileReader:System.IO.BinaryReader) =
  let reg_map_len = traceFileReader.ReadUInt64 ()
  let reg_map_buffer = traceFileReader.ReadBytes (int reg_map_len)
  (reg_map_len, reg_map_buffer)

(*=====================================================================================================================*)

let deserializeMemMap<'TAddress> (traceFileReader:System.IO.BinaryReader) =
  let memMapLength =
    match typeof<'TAddress> with
      | t when t = typeof<uint32> -> int (traceFileReader.ReadUInt32 ())
      | t when t = typeof<uint64> -> int (traceFileReader.ReadUInt64 ())
      | _ -> failwith "unknown type parameter"
  let memMapBuffer = traceFileReader.ReadBytes memMapLength
  memMapBuffer

let deserializeMemMapX8664 (traceFileReader:System.IO.BinaryReader) =
  let mem_map_len = traceFileReader.ReadUInt64 ()
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

let deserializeDynamicTrace<'TAddress when 'TAddress : unmanaged and 'TAddress : comparison> (traceFileReader:System.IO.BinaryReader) =
  let insDynamicTrace = DynamicTrace<'TAddress>()
  let mutable insStaticMap = Map.empty
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
    insDynamicTrace.Add address
    if not <| Map.containsKey address insStaticMap then
      insStaticMap <- Map.add address { Address = address;
                                        NextAddress = next_address;
                                        Mnemonic = mnemonic_string;
                                        ThreadId = thread_id } insStaticMap
  (insStaticMap, insDynamicTrace)

let deserializeTraceX8664 (traceFileReader:System.IO.BinaryReader) =
  let trace = ResizeArray<_>()
  while (traceFileReader.BaseStream.Position <> traceFileReader.BaseStream.Length) do
    let serialized_length = traceFileReader.ReadUInt64 ()
    let address = traceFileReader.ReadUInt64 ()
    let next_address = traceFileReader.ReadUInt64 ()
    deserializeOpcodeX8664 traceFileReader |> ignore
    let mnemonic_string = deserializeMnemonicX8664 traceFileReader
    Printf.printfn "%s" mnemonic_string
    deserializeRegMapX8664 traceFileReader |> ignore
    deserializeRegMapX8664 traceFileReader |> ignore
    deserializeMemMapX8664 traceFileReader |> ignore
    deserializeMemMapX8664 traceFileReader |> ignore
    let thread_id = traceFileReader.ReadUInt32 ()
    trace.Add { Address = address;
                NextAddress = next_address;
                Mnemonic = mnemonic_string;
                ThreadId = thread_id }
  trace

(*=====================================================================================================================*)

let printTrace<'TAddress when 'TAddress : unmanaged> (trace:ResizeTrace<'TAddress>) =
  for ins in trace do
    match typeof<'TAddress> with
      | t when t = typeof<uint32> -> Printf.printfn "0x%x %s" (unbox<uint32> ins.Address) ins.Mnemonic
      | t when t = typeof<uint64> -> Printf.printfn "0x%x %s" (unbox<uint64> ins.Address) ins.Mnemonic
      | _ -> failwith "unknown type parameter"
  Printf.printfn "%u instructions parsed" (ResizeArray.length trace)

let printTraceX8664 (trace:ResizeArray<Instruction<uint64>>) =
  for ins in trace do
    Printf.printfn "0x%x %s" ins.Address ins.Mnemonic
  Printf.printfn "%u instructions parsed" (ResizeArray.length trace)

(*=====================================================================================================================*)

let computeInstructionStaticMap<'TAddress when 'TAddress : unmanaged and 'TAddress : comparison> (trace:ResizeTrace<'TAddress>) =
  let mutable insMap = Map.empty
  for trIns in trace do
    if not <| Map.containsKey trIns.Address insMap then
      insMap <- Map.add trIns.Address trIns insMap
  insMap
  // let insList = ref []
  // for trIns in trace do
  //   if not <| List.exists (fun ins -> ins.Address = trIns.Address) !insList then
  //     insList := trIns :: !insList
  // List.rev !insList

let constructCfgFromTraces<'TAddress when 'TAddress : unmanaged and 'TAddress : comparison> (traces:ResizeTrace<'TAddress> list) =
  let cfgEdges = ref []
  List.iter (fun trace ->
             let allEdges = Seq.pairwise <| ResizeArray.toSeq trace
             for trEdge in allEdges do
             if not <| List.exists (fun edge ->
                                    (fst edge).Address = (fst trEdge).Address &&
                                    (snd edge).Address = (snd trEdge).Address) !cfgEdges then
               cfgEdges := trEdge :: !cfgEdges) traces
  let cfg_short_edges = List.map (fun (fromVertex, toVertex) ->
                                  QuickGraph.SEdge(fromVertex.Address, toVertex.Address)) !cfgEdges
  QuickGraph.GraphExtensions.ToBidirectionalGraph cfg_short_edges

let computeLinearList<'TAddress when 'TAddress : unmanaged and 'TAddress : comparison> (startInsAddr:'TAddress) (cfg:SimpleCFG<'TAddress>) =
  let instLinearList = ref []
  let dfsAlgo = QuickGraph.Algorithms.Search.DepthFirstSearchAlgorithm(cfg)
  dfsAlgo.SetRootVertex(startInsAddr)
  dfsAlgo.add_DiscoverVertex(fun vertex -> instLinearList := vertex :: !instLinearList)
  dfsAlgo.Compute()
  List.rev !instLinearList

let addInsToBlock<'TAddress when 'TAddress : unmanaged and 'TAddress : comparison> (insAddr : 'TAddress) (basicBlock : BasicBlock<'TAddress> byref) =
  if not <| List.contains insAddr basicBlock then
    basicBlock <- insAddr :: basicBlock
  // if List.contains insAddr basicBlock then
  //   basicBlock
  // else
  //   insAddr::basicBlock
let saveBasicBlock<'TAddress when 'TAddress : unmanaged and 'TAddress : comparison> (basicBlock : BasicBlock<'TAddress>) (basicBlocks : BasicBlock<'TAddress> list byref) =
  basicBlocks <- (List.rev basicBlock) :: basicBlocks

let computeBasicBlocks<'TAddress when 'TAddress : unmanaged and 'TAddress : comparison> (startInsAddr:'TAddress) (cfg:SimpleCFG<'TAddress>) =
  let mutable bBs = []
  let mutable currentBb = []
  let linearList = computeLinearList startInsAddr cfg
  for insAddr in linearList do
    if List.isEmpty currentBb then currentBb <- [insAddr]
    if cfg.InDegree(insAddr) = 1 then
      // currentBb := addInsToBlock insAddr !currentBb
      addInsToBlock insAddr &currentBb
      if cfg.OutDegree(insAddr) <> 1 then
        // bBs <- (List.rev currentBb) :: bBs
        saveBasicBlock currentBb &bBs
        currentBb <- []
    else
      bBs <- currentBb :: bBs
      currentBb <- [insAddr]
      if cfg.OutDegree(insAddr) > 1 then
        // bBs <- (List.rev currentBb) :: bBs
        saveBasicBlock currentBb &bBs
        currentBb <- []
  bBs

let getSimpleDestinationVertices<'TAddress when 'TAddress : unmanaged and 'TAddress : comparison> (basicBlock:BasicBlock<'TAddress>) (cfg:SimpleCFG<'TAddress>) =
  let lastVertex = List.reduce (fun f s -> s) basicBlock
  let outEdges = cfg.OutEdges(lastVertex)
  let mutable outVertices = []
  for edge in outEdges do
    outVertices <- edge.Target :: outVertices
  outVertices

let getSimpleSourceVertices<'TAddress when 'TAddress : unmanaged and 'TAddress : comparison> (basicBlock : BasicBlock<'TAddress>) (cfg : SimpleCFG<'TAddress>) =
  let firstVertex = List.head basicBlock
  let inEdges = cfg.InEdges(firstVertex)
  let mutable inVertices = []
  for edge in inEdges do
    inVertices <- edge.Target :: inVertices
  inVertices

let constructBasicBlockCfg<'TAddress when 'TAddress : unmanaged and 'TAddress : comparison> (basicBlocks : BasicBlock<'TAddress> list) (cfg : SimpleCFG<'TAddress>) =
  let mutable basicBlockPairs = []
  for srcBb in basicBlocks do
    for dstBb in basicBlocks do
      let simpleOutVertices = getSimpleDestinationVertices srcBb cfg
      if List.contains (List.head dstBb) simpleOutVertices then
        basicBlockPairs <- (srcBb, dstBb) :: basicBlockPairs
  let basicBlocksEdges = List.map (fun (src, dst) -> QuickGraph.SEdge(src, dst)) basicBlockPairs
  QuickGraph.GraphExtensions.ToBidirectionalGraph basicBlocksEdges

let stringOfInstruction<'TAddress when 'TAddress : unmanaged and 'TAddress : comparison> (staticInss : InstructionMap<'TAddress>) (insAddr : 'TAddress) =
  match typeof<'TAddress> with
    | t when t = typeof<uint32> -> (Printf.sprintf "0x%016x  %s" (unbox<uint32> insAddr) (staticInss.[insAddr]).Mnemonic)
    | t when t = typeof<uint64> -> (Printf.sprintf "0x%016x  %s" (unbox<uint32> insAddr) (staticInss.[insAddr]).Mnemonic)
    | _ -> failwith "unknown type parameter"

let getBasicBlockLabel<'TAddress when 'TAddress : unmanaged and 'TAddress : comparison> (staticInss : InstructionMap<'TAddress>) (basicBlock : BasicBlock<'TAddress>) =
  let basicBlockLabel = ref ""
  List.iter (fun insAddr ->
             basicBlockLabel := (Printf.sprintf "%s\l" <|
                                 stringOfInstruction staticInss insAddr) + !basicBlockLabel) basicBlock
  !basicBlockLabel

type BasicBlockDotEngine() =
  interface QuickGraph.Graphviz.IDotEngine with
    member this.Run (imgType:QuickGraph.Graphviz.Dot.GraphvizImageType, dotString:string, outputFilename:string) =
      System.IO.File.WriteAllText(outputFilename, dotString)
      outputFilename

let printBasicBlockCfg<'TAddress when 'TAddress : unmanaged and 'TAddress : comparison> (staticInss : InstructionMap<'TAddress>) (bbCFG : BasicBlockCFG<'TAddress>) outputFilename =
  let graphvizFormat = QuickGraph.Graphviz.GraphvizAlgorithm(bbCFG)
  graphvizFormat.FormatVertex.Add(fun args ->
                                  let basicBlock = args.Vertex
                                  args.VertexFormatter.Label <- getBasicBlockLabel staticInss basicBlock
                                  args.VertexFormatter.Shape <- QuickGraph.Graphviz.Dot.GraphvizVertexShape.Box
                                  args.VertexFormatter.Style <- QuickGraph.Graphviz.Dot.GraphvizVertexStyle.Rounded)
  graphvizFormat.Generate(new BasicBlockDotEngine(), outputFilename) |> ignore

(*=====================================================================================================================*)

type TraceRangeFilterStates =
  | BeforeStart = 0
  | BetweenStartStop = 1
  | AfterStop = 2

let filterTraceRange<'TAddress when 'TAddress : unmanaged and 'TAddress : comparison> (startAddr:'TAddress, stopAddr:'TAddress) (trace:DynamicTrace<'TAddress>) =
  let filterredTrace = DynamicTrace<'TAddress>()
  let mutable filterState:TraceRangeFilterStates = TraceRangeFilterStates.BeforeStart
  for ins in trace do
    match filterState with
      | TraceRangeFilterStates.BeforeStart ->
        if ins = startAddr then
          filterState <- TraceRangeFilterStates.BetweenStartStop
          filterredTrace.Add ins
      | TraceRangeFilterStates.BetweenStartStop ->
        if ins = stopAddr then
          filterState <- TraceRangeFilterStates.AfterStop
        filterredTrace.Add ins
      | TraceRangeFilterStates.AfterStop -> ()
  filterredTrace

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
