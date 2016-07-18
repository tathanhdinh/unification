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

let hexStringOfValue<'TAddress when 'TAddress : unmanaged> (insAddr:'TAddress) =
  match box insAddr with
    | :? uint32 as uint32Addr -> Printf.sprintf "0x%x" uint32Addr
    | :? uint64 as uint64Addr -> Printf.sprintf "0x%x" uint64Addr
    | _ -> failwith "unknown type parameter"

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
    let nextAddress =
      match typeof<'TAddress> with
        | t when t = typeof<uint32> -> traceFileReader.ReadUInt32 () |> unbox<'TAddress>
        | t when t = typeof<uint64> -> traceFileReader.ReadUInt64 () |> unbox<'TAddress>
        | _ -> failwith "unknown type parameter"
    deserializeOpcode<'TAddress> traceFileReader |> ignore
    let mnemonicString = deserializeMnemonic<'TAddress> traceFileReader
    deserializeRegMap<'TAddress> traceFileReader |> ignore
    deserializeRegMap<'TAddress> traceFileReader |> ignore
    deserializeMemMap<'TAddress> traceFileReader |> ignore
    deserializeMemMap<'TAddress> traceFileReader |> ignore
    let threadId = traceFileReader.ReadUInt32 ()
    insDynamicTrace.Add address
    if not <| Map.containsKey address insStaticMap then
      insStaticMap <- Map.add address { Address = address;
                                        NextAddress = nextAddress;
                                        Mnemonic = mnemonicString;
                                        ThreadId = threadId } insStaticMap
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

let printDynamicTrace<'TAddress when 'TAddress : unmanaged and 'TAddress : comparison> (insMap:InstructionMap<'TAddress>) (trace:DynamicTrace<'TAddress>) =
  for insAddr in trace do
    Printf.printfn "%s  %s" (hexStringOfValue insAddr) (insMap.[insAddr]).Mnemonic

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

let constructSimpleCfgFromTraces<'TAddress when 'TAddress : unmanaged and 'TAddress : comparison> (traces:DynamicTrace<'TAddress> list) =
  // let mutable allVertexPairs = []
  let allVertexPairs = ResizeArray<_>()
  for trace in traces do
    let traceVertexPairs = Seq.pairwise <| ResizeArray.toSeq trace
    for vertexPair in traceVertexPairs do
      if not <| Seq.exists (fun edge -> edge = vertexPair) allVertexPairs then
        // allVertexPairs <- vertexPair :: allVertexPairs
        allVertexPairs.Add vertexPair
  let basicEdges = Seq.map (fun (fromAddr, toAddr) -> QuickGraph.SEdge(fromAddr, toAddr)) allVertexPairs
  QuickGraph.GraphExtensions.ToBidirectionalGraph basicEdges
  // List.iter (fun trace ->
  //            let allEdges = Seq.pairwise <| ResizeArray.toSeq trace
  //            for trEdge in allEdges do
  //              if not <| List.exists (fun edge ->
  //                                     (fst edge).Address = (fst trEdge).Address &&
  //                                     (snd edge).Address = (snd trEdge).Address) !vertexPairs then
  //               vertexPairs := trEdge :: !vertexPairs) traces
  // let cfg_short_edges = List.map (fun (fromVertex, toVertex) ->
  //                                 QuickGraph.SEdge(fromVertex.Address, toVertex.Address)) !vertexPairs
  // QuickGraph.GraphExtensions.ToBidirectionalGraph cfg_short_edges

type SimpleDotEngine() =
  interface QuickGraph.Graphviz.IDotEngine with
    member this.Run (imgType:QuickGraph.Graphviz.Dot.GraphvizImageType, dotString:string, outputFilename:string) =
      System.IO.File.WriteAllText(outputFilename, dotString)
      outputFilename

let printSimpleCfg<'TAddress when 'TAddress : unmanaged and 'TAddress : comparison> (insMap : InstructionMap<'TAddress>) (simpleCFG : SimpleCFG<'TAddress>) outputFilename =
  let graphvizFormat = QuickGraph.Graphviz.GraphvizAlgorithm(simpleCFG)
  graphvizFormat.FormatVertex.Add(fun args ->
                                  let insAddr = args.Vertex
                                  args.VertexFormatter.Label <- Printf.sprintf "%s  %s"  (hexStringOfValue insAddr) (insMap.[insAddr]).Mnemonic
                                  args.VertexFormatter.Font <- QuickGraph.Graphviz.Dot.GraphvizFont("Source Code Pro", 12.0f)
                                  args.VertexFormatter.Shape <- QuickGraph.Graphviz.Dot.GraphvizVertexShape.Box
                                  args.VertexFormatter.Style <- QuickGraph.Graphviz.Dot.GraphvizVertexStyle.Rounded)
  graphvizFormat.Generate(new SimpleDotEngine(), outputFilename) |> ignore

let computeLinearList<'TAddress when 'TAddress : unmanaged and 'TAddress : comparison> (startInsAddr:'TAddress) (cfg:SimpleCFG<'TAddress>) =
  let instLinearList = ref []
  let dfsAlgo = QuickGraph.Algorithms.Search.DepthFirstSearchAlgorithm(cfg)
  dfsAlgo.SetRootVertex(startInsAddr)
  dfsAlgo.add_DiscoverVertex(fun vertex -> instLinearList := vertex :: !instLinearList)
  dfsAlgo.Compute()
  Printf.printfn "linear list: %d instructions" <| List.length !instLinearList
  List.rev !instLinearList

let addInsToBlock<'TAddress when 'TAddress : unmanaged and 'TAddress : comparison> (insAddr : 'TAddress) (basicBlock : BasicBlock<'TAddress> byref) =
 if not <| List.contains insAddr basicBlock then
    basicBlock <- insAddr :: basicBlock

let saveBasicBlock<'TAddress when 'TAddress : unmanaged and 'TAddress : comparison> (basicBlock : BasicBlock<'TAddress> byref) (basicBlocks : BasicBlock<'TAddress> list byref) =
  basicBlocks <- (List.rev basicBlock) :: basicBlocks
  basicBlock <- []

let computeBasicBlocks<'TAddress when 'TAddress : unmanaged and 'TAddress : comparison> (startInsAddr:'TAddress) (cfg:SimpleCFG<'TAddress>) =
  let mutable allBasicBlocks = []
  let mutable currentBlock = [startInsAddr]
  match computeLinearList startInsAddr cfg with
    | _::linearList ->
      // Printf.printfn "start linear list"
      // List.iter (hexStringOfValue >> Printf.printfn "%s") linearList
      // Printf.printfn "end linear list"
      for insAddr in linearList do
        if List.isEmpty currentBlock then currentBlock <- [insAddr]
        else
          let prevInsAddr = List.head currentBlock
          if cfg.ContainsEdge(prevInsAddr, insAddr) && cfg.InDegree(insAddr) = 1 then
            currentBlock <- insAddr :: currentBlock
          else
            saveBasicBlock &currentBlock &allBasicBlocks
            currentBlock <- [insAddr]

        if cfg.OutDegree(insAddr) > 1 then saveBasicBlock &currentBlock &allBasicBlocks

        //   if cfg.OutDegree(insAddr) <> 1 then
        //     saveBasicBlock &currentBb &bBs
        // else
        //   saveBasicBlock &currentBb &bBs
        //   currentBb <- [insAddr]
        //   if cfg.OutDegree(insAddr) > 1 then
        //     saveBasicBlock &currentBb &bBs
      // List.rev bBs
    | _ -> failwith "empty DFS traversing path"
  allBasicBlocks

let getSimpleDestinationVertices<'TAddress when 'TAddress : unmanaged and 'TAddress : comparison> (basicBlock:BasicBlock<'TAddress>) (cfg:SimpleCFG<'TAddress>) =
  let lastVertex = List.reduce (fun _ s -> s) basicBlock
  let outEdges = Seq.toList <| cfg.OutEdges(lastVertex)
  List.map (fun (edge:QuickGraph.SEdge<'TAddress>) -> edge.Target) outEdges
  // let mutable outVertices = []
  // for edge in outEdges do
  //   outVertices <- edge.Target :: outVertices
  // // List.iter (fun addr -> Printf.printfn "%s -> %s" (hexStringOfValue lastVertex) (hexStringOfValue addr)) outVertices
  // outVertices

let getSimpleSourceVertices<'TAddress when 'TAddress : unmanaged and 'TAddress : comparison> (basicBlock : BasicBlock<'TAddress>) (cfg : SimpleCFG<'TAddress>) =
  let firstVertex = List.head basicBlock
  let inEdges = cfg.InEdges(firstVertex)
  let mutable inVertices = []
  for edge in inEdges do
    inVertices <- edge.Target :: inVertices
  inVertices

let constructBasicBlockCfg<'TAddress when 'TAddress : unmanaged and 'TAddress : comparison> (basicBlocks : BasicBlock<'TAddress> list) (cfg : SimpleCFG<'TAddress>) =
  // let mutable basicBlockPairs = []
  let basicBlockPairs = ResizeArray<_>()
  for srcBb in basicBlocks do
    for dstBb in basicBlocks do
      let simpleOutVertices = getSimpleDestinationVertices srcBb cfg
      if List.contains (List.head dstBb) simpleOutVertices then
        basicBlockPairs.Add (srcBb, dstBb)
  let basicBlocksEdges = Seq.map (fun (src, dst) -> QuickGraph.SEdge(src, dst)) (Seq.distinct basicBlockPairs)
  QuickGraph.GraphExtensions.ToBidirectionalGraph basicBlocksEdges

let stringOfInstruction<'TAddress when 'TAddress : unmanaged and 'TAddress : comparison> (staticInss : InstructionMap<'TAddress>) (insAddr : 'TAddress) =
  Printf.sprintf "%s  %s" (hexStringOfValue insAddr) (staticInss.[insAddr].Mnemonic)
  // match typeof<'TAddress> with
  //   | t when t = typeof<uint32> -> (Printf.sprintf "0x%016x  %s" (unbox<uint32> insAddr) (staticInss.[insAddr]).Mnemonic)
  //   | t when t = typeof<uint64> -> (Printf.sprintf "0x%016x  %s" (unbox<uint32> insAddr) (staticInss.[insAddr]).Mnemonic)
  //   | _ -> failwith "unknown type parameter"

let getBasicBlockLabel<'TAddress when 'TAddress : unmanaged and 'TAddress : comparison> (staticInss : InstructionMap<'TAddress>) (basicBlock : BasicBlock<'TAddress>) =
  List.fold (+) "" <| List.map (fun insAddr -> (Printf.sprintf "%s\l" <| stringOfInstruction staticInss insAddr)) basicBlock
  // let mutable basicBlockStr = ""
  // for insAddr in basicBlock do
  //   basicBlockStr <- basicBlockStr + (Printf.sprintf "%s\l" <| stringOfInstruction staticInss insAddr)
  // basicBlockStr

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
                                  args.VertexFormatter.Font <- QuickGraph.Graphviz.Dot.GraphvizFont("Source Code Pro", 12.0f)
                                  args.VertexFormatter.Shape <- QuickGraph.Graphviz.Dot.GraphvizVertexShape.Box
                                  args.VertexFormatter.Style <- QuickGraph.Graphviz.Dot.GraphvizVertexStyle.Rounded)
  graphvizFormat.Generate(new BasicBlockDotEngine(), outputFilename) |> ignore

(*=====================================================================================================================*)

type TraceRangeFilterStates =
  | BeforeStart = 0
  | BetweenStartStop = 1
  | AfterStop = 2

// keep all instructions in [start, end]
let selectBoundedInterval<'TAddress when 'TAddress : unmanaged and 'TAddress : comparison> (startAddr:'TAddress, stopAddr:'TAddress) (trace:DynamicTrace<'TAddress>) =
  let filteredTrace = DynamicTrace<'TAddress>()
  let mutable filterState = TraceRangeFilterStates.BeforeStart
  for insAddr in trace do
    match filterState with
      | TraceRangeFilterStates.BeforeStart ->
        if insAddr = startAddr then
          filterState <- TraceRangeFilterStates.BetweenStartStop
          filteredTrace.Add insAddr
      | TraceRangeFilterStates.BetweenStartStop ->
        filteredTrace.Add insAddr
        if insAddr = stopAddr then filterState <- TraceRangeFilterStates.AfterStop
      | TraceRangeFilterStates.AfterStop -> ()
      | _ -> failwith "invalid filter state"
  filteredTrace

// remove all instructions in (start, end)
let removeOpenInterval<'TAddress when 'TAddress : unmanaged and 'TAddress : comparison> (startAddr:'TAddress, stopAddr:'TAddress) (trace:DynamicTrace<'TAddress>) =
  let filteredTrace = DynamicTrace<'TAddress>()
  let mutable filterState = TraceRangeFilterStates.BeforeStart
  for insAddr in trace do
    match filterState with
      | TraceRangeFilterStates.BeforeStart ->
        filteredTrace.Add insAddr
        if insAddr = startAddr then filterState <- TraceRangeFilterStates.BetweenStartStop
      | TraceRangeFilterStates.BetweenStartStop ->
        if insAddr = stopAddr then
          filterState <- TraceRangeFilterStates.AfterStop
          filteredTrace.Add insAddr
      | TraceRangeFilterStates.AfterStop ->
        filteredTrace.Add insAddr
      | _ -> failwith "invalid filter state"
  filteredTrace

// keep all instructions in [start, end)
let filterLeftBoundedInterval<'TAddress when 'TAddress : unmanaged and 'TAddress : comparison> (startAddr:'TAddress, stopAddr:'TAddress) (trace:DynamicTrace<'TAddress>) =
  let filteredTrace = DynamicTrace<'TAddress>()
  let mutable filterState = TraceRangeFilterStates.BeforeStart
  for ins in trace do
    match filterState with
      | TraceRangeFilterStates.BeforeStart ->
        if (ins = startAddr) then
          filterState <- TraceRangeFilterStates.BetweenStartStop
          filteredTrace.Add ins
      | TraceRangeFilterStates.BetweenStartStop ->
        if (ins = stopAddr) then
          filterState <- TraceRangeFilterStates.AfterStop
        else
          filteredTrace.Add ins
      | TraceRangeFilterStates.AfterStop -> ()
      | _ -> failwith "invalid filter state"

// keep all instructions in (start, end]
let filterRightBoundedInterval<'TAddress when 'TAddress : unmanaged and 'TAddress : comparison> (startAddr:'TAddress, stopAddr:'TAddress) (trace:DynamicTrace<'TAddress>) =
  let filteredTrace = DynamicTrace<'TAddress>()
  let mutable filterState = TraceRangeFilterStates.BeforeStart
  for ins in trace do
    match filterState with
      | TraceRangeFilterStates.BeforeStart ->
        if (ins = startAddr) then filterState <- TraceRangeFilterStates.BetweenStartStop
      | TraceRangeFilterStates.BetweenStartStop ->
        filteredTrace.Add ins
        if (ins = startAddr) then filterState <- TraceRangeFilterStates.AfterStop
      | TraceRangeFilterStates.AfterStop -> ()
      | _ -> failwith "invalid filter state"

// remove all instructions in (-inf, pivot]
let removeRightBoundedInterval<'TAddress when 'TAddress : unmanaged and 'TAddress : comparison> (pivotAddr:'TAddress) (trace:DynamicTrace<'TAddress>) =
  let filteredTrace = DynamicTrace<'TAddress>()
  let mutable pivotReached = false
  for insAddr in trace do
    if pivotReached then
      filteredTrace.Add insAddr
    else
      if insAddr = pivotAddr then pivotReached <- true
  filteredTrace

// remove all instruction in [pivot, +inf)
let removeLeftBoundedInterval<'TAddress when 'TAddress : unmanaged and 'TAddress : comparison> (pivotAddr:'TAddress) (trace:DynamicTrace<'TAddress>) =
  let filteredTrace = DynamicTrace<'TAddress>()
  let mutable pivotReached = false
  for insAddr in trace do
    if insAddr = pivotAddr then pivotReached <- true
    if not pivotReached then filteredTrace.Add insAddr
  filteredTrace

// filter all instructions of a "standard" call
let filterStandardCall<'TAddress when 'TAddress : unmanaged and 'TAddress : comparison> (callInsAddr:'TAddress) (staticInsMap:InstructionMap<'TAddress>) (trace:DynamicTrace<'TAddress>) =
  let callIns = staticInsMap.[callInsAddr]
  let nextInsAddr = callIns.NextAddress
  removeOpenInterval (callInsAddr, nextInsAddr) trace

(*=====================================================================================================================*)

[<EntryPoint>]
let main argv =
  if Array.length argv <> 1 then
    Printf.printfn "give a serialized trace file from the command line (e.g. analyzer trace_file)"
    0
  else
    let timer = new System.Diagnostics.Stopwatch()
    timer.Start()
    use traceFileReader = new System.IO.BinaryReader(System.IO.File.OpenRead(argv.[0]))
    let (addrIntSize, boolSize, threadIdSize) = parseTraceHeader traceFileReader
    Printf.printfn "data sizes: (ADDRINT: %d), (BOOL: %d), (THREADID: %d)" addrIntSize boolSize threadIdSize
    if addrIntSize = (byte 8) then
      let (insMap, insTrace) = deserializeDynamicTrace<uint64> traceFileReader
      // printDynamicTrace insMap insTrace
      Printf.printfn "parsed instructions: %d" (Seq.length insTrace)
      // let filteredTrace = selectBoundedInterval<uint64> (0x4004f0UL, 0x400501UL) insTrace
      let filteredTrace = insTrace
      Printf.printfn "trace length: %d" <| Seq.length filteredTrace
      // printDynamicTrace insMap filteredTrace
      let rootInsAddr = Seq.head filteredTrace
      Printf.printfn "root address: 0x%x" rootInsAddr
      Printf.printf "constructing simple CFG..."
      let basicCFG = constructSimpleCfgFromTraces<uint64> [filteredTrace]
      Printf.printfn " done."
      // printSimpleCfg insMap basicCFG "hello_simple.dot"
      Printf.printf "computing basic blocks..."
      let basicBlocks = computeBasicBlocks rootInsAddr basicCFG
      Printf.printfn "basic blocks: %d" <| List.length basicBlocks
      // List.iter (fun bb -> Printf.printfn "=====\n%s\n====="  <| (getBasicBlockLabel insMap bb)) basicBlocks
      // for bb in basicBlocks do
      //   Printf.printfn "start block"
      //   for insAddr in bb do
      //     Printf.printfn "%s" <| hexStringOfValue insAddr
      //   Printf.printfn "end block"
      let basicBlockCFG = constructBasicBlockCfg basicBlocks basicCFG
      printBasicBlockCfg insMap basicBlockCFG "hello.dot"
      // filteredTrace <- filterStandardCall<uint64> 0x4004f9UL insMap filteredTrace
      // // ignore filteredTrace
      // printDynamicTrace insMap filteredTrace
      // deserializeTrace<uint64> traceFileReader |> printTrace<uint64>
      // let trace_length = getTraceLength<uint64> traceFileReader
      // Printf.printfn "number of serialized instructions: %d" trace_length
    else
      // deserializeTrace<uint32> traceFileReader |> printTrace<uint32>
      let trace_length = getTraceLength<uint32> traceFileReader
      Printf.printfn "serialized instructions: %d" trace_length
    Printf.printfn "elapsed time: %i ms" timer.ElapsedMilliseconds
    1
