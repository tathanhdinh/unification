type Instruction<'TAddress> = { Address : 'TAddress;
                                NextAddress : 'TAddress;
                                Mnemonic: string
                                ThreadId : uint32 }

type ControlFlow<'TAddress> = Instruction<'TAddress> * Instruction<'TAddress>

type ControlFlows<'TAddress> = Collections.ResizeArray<ControlFlow<'TAddress>>

type BaseCfg<'TAddress when 'TAddress : comparison> = QuickGraph.BidirectionalGraph<Instruction<'TAddress>, 
                                                                                    QuickGraph.SEdge<Instruction<'TAddress>>>

type NativeTrace<'TAddress> = Collections.ResizeArray<Instruction<'TAddress>>

type LocationMap<'TAddress when 'TAddress : comparison> = System.Collections.Generic.Dictionary<'TAddress,
                                                                                                 Instruction<'TAddress>>

//type SmInstruction<'TAddress> = { Address : 'TAddress; 
//                                  InsIndex : int }

//type Trace<'TAddress when 'TAddress : comparison> = Collections.ResizeArray<SmInstruction<'TAddress>>

type BasicBlock<'TAddress when 'TAddress : comparison> = Instruction<'TAddress> list

type BasicBlocks<'TAddress when 'TAddress : comparison> = Collections.ResizeArray<BasicBlock<'TAddress>>

type BasicBlockCfg<'TAddress when 'TAddress : comparison> = QuickGraph.BidirectionalGraph<BasicBlock<'TAddress>,
                                                                                          QuickGraph.SEdge<BasicBlock<'TAddress>>>


(*================================================================================================================*)

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

let genericRead<'TAddress when 'TAddress : unmanaged> (traceFileReader : System.IO.BinaryReader) =
  match typeof<'TAddress> with
    | t when t = typeof<uint32> -> unbox<'TAddress> (box <| traceFileReader.ReadUInt32())
    | t when t = typeof<uint64> -> unbox<'TAddress> (box <| traceFileReader.ReadUInt64())
    | _ -> failwith "unknown type parameter"

let genericReadInt<'TAddress when 'TAddress : unmanaged> (traceFileReader : System.IO.BinaryReader) =
  match typeof<'TAddress> with
    | t when t = typeof<uint32> -> int <| traceFileReader.ReadUInt32()
    | t when t = typeof<uint64> -> int <| traceFileReader.ReadUInt64()
    | _ -> failwith "unknown type parameter"

(*================================================================================================================*)

let getTraceLengthGeneric<'TAddress when 'TAddress : unmanaged> (traceFileReader : System.IO.BinaryReader) = 
  let mutable traceLength = 0u
  while (traceFileReader.BaseStream.Position <> traceFileReader.BaseStream.Length) do
    let insLength = genericReadInt<'TAddress> traceFileReader
    traceFileReader.BaseStream.Seek (int64 insLength, System.IO.SeekOrigin.Current) |> ignore
    traceLength <- traceLength + 1u
  traceLength

(*================================================================================================================*)

let deserializeOpcodeGeneric<'TAddress when 'TAddress : unmanaged> (traceFileReader:System.IO.BinaryReader) =
  let opcodeSize = genericReadInt<'TAddress> traceFileReader
  let opcodeBuffer = traceFileReader.ReadBytes opcodeSize
  opcodeBuffer

(*================================================================================================================*)

let deserializeMnemonicGeneric<'TAddress when 'TAddress : unmanaged> (traceFileReader:System.IO.BinaryReader) =
  let mnemonicLength = genericReadInt<'TAddress> traceFileReader
  let mnemonicString = traceFileReader.ReadBytes mnemonicLength
  System.Text.Encoding.ASCII.GetString mnemonicString

(*================================================================================================================*)

let deserializeRegMapGeneric<'TAddress when 'TAddress : unmanaged> (traceFileReader:System.IO.BinaryReader) =
  let regMapLength = genericReadInt<'TAddress> traceFileReader
  let regMapBuffer = traceFileReader.ReadBytes regMapLength
  regMapBuffer

(*================================================================================================================*)

let deserializeMemMapGeneric<'TAddress when 'TAddress : unmanaged> (traceFileReader:System.IO.BinaryReader) =
  let memMapLength = genericReadInt<'TAddress> traceFileReader
  let memMapBuffer = traceFileReader.ReadBytes memMapLength
  memMapBuffer

(*================================================================================================================*)

let deserializeTraceGeneric<'TAddress  when 'TAddress : unmanaged and 
                                            'TAddress : comparison> (traceFileReader:System.IO.BinaryReader) =
  let mutable instructionCount = 0u
  let programControlFlow = new ControlFlows<'TAddress>()
  let mutable prevInstruction = None
  while traceFileReader.BaseStream.Position <> traceFileReader.BaseStream.Length do
    instructionCount <- instructionCount + 1u
    let serializedLength = genericRead<'TAddress> traceFileReader
    let address = genericRead<'TAddress> traceFileReader
    let nextAddress = genericRead<'TAddress> traceFileReader
    deserializeOpcodeGeneric<'TAddress> traceFileReader |> ignore
    let mnemonicStr = deserializeMnemonicGeneric<'TAddress> traceFileReader
    deserializeRegMapGeneric<'TAddress> traceFileReader |> ignore
    deserializeRegMapGeneric<'TAddress> traceFileReader |> ignore
    deserializeMemMapGeneric<'TAddress> traceFileReader |> ignore
    deserializeMemMapGeneric<'TAddress> traceFileReader |> ignore
    let threadId = traceFileReader.ReadUInt32 ()
    let newInstruction = { Address = address;
                           NextAddress = nextAddress;
                           Mnemonic = mnemonicStr;
                           ThreadId = threadId }
    match prevInstruction with
    | None -> ignore ()
    | Some lastInstruction -> 
      let currentFlow = (lastInstruction, newInstruction)
      if programControlFlow.BinarySearch(currentFlow) < 0 then
        programControlFlow.Add(currentFlow)
    prevInstruction <- Some newInstruction
  (instructionCount, programControlFlow)

(*================================================================================================================*)

let constructBaseCfgFromControlFlows<'TAddress when 'TAddress : comparison> (controlFlows:ControlFlows<'TAddress>) = 
  let edges = Collections.Seq.map (fun (fromIns, toIns) -> QuickGraph.SEdge(fromIns, toIns)) controlFlows
//  let edges = controlFlows.ToArray() 
//            |> Collections.Seq.ofArray 
//            |> Collections.Seq.map (fun (fromIns, toIns) -> QuickGraph.SEdge(fromIns, toIns))
  QuickGraph.GraphExtensions.ToBidirectionalGraph edges

(*================================================================================================================*)

let buildBasicBlocks<'TAddress when 'TAddress : comparison> (baseCfg:BaseCfg<'TAddress>) 
                                                            (entryPoint:Instruction<'TAddress>) =
  let discoveredVertices = new NativeTrace<'TAddress>()
  let dfsAlgoInstance = QuickGraph.Algorithms.Search.DepthFirstSearchAlgorithm(baseCfg)
  dfsAlgoInstance.SetRootVertex(entryPoint)
  dfsAlgoInstance.add_DiscoverVertex(fun vertex -> discoveredVertices.Add vertex)
  dfsAlgoInstance.Compute()
  let basicBlocks = new BasicBlocks<'TAddress>()
  let mutable currentBasicBlock = []
  for instruction in discoveredVertices do
    if currentBasicBlock.IsEmpty then
      currentBasicBlock <- [instruction]
     else
      let prevInstruction = List.head currentBasicBlock
      if baseCfg.ContainsEdge(prevInstruction, instruction) && baseCfg.InDegree(instruction) = 1 then
        currentBasicBlock <- instruction :: currentBasicBlock
      else
        basicBlocks.Add <| List.rev currentBasicBlock
        currentBasicBlock <- [instruction]
      
    if baseCfg.OutDegree(instruction) > 1 then
      basicBlocks.Add <| List.rev currentBasicBlock
      currentBasicBlock <- []
        
  if not currentBasicBlock.IsEmpty then
    basicBlocks.Add <| List.rev currentBasicBlock
  basicBlocks

(*================================================================================================================*)

let targetInstructions<'TAddress when 'TAddress : comparison> (basicBlock:BasicBlock<'TAddress>) 
                                                              (baseCfg:BaseCfg<'TAddress>) =
  let lastInstruction = basicBlock.[basicBlock.Length - 1]
  let outControlFlows = baseCfg.OutEdges(lastInstruction)
  Seq.map (fun (edge:QuickGraph.SEdge<Instruction<'TAddress>>) -> edge.Target) outControlFlows

let constructBasicBlockCfg<'TAddress when 'TAddress : comparison> (basicBlocks:BasicBlocks<'TAddress>) 
                                                                  (controlFlows:ControlFlows<'TAddress>) =
  let basicBlockControlFlows = new Collections.ResizeArray<_>()
  for srcBb in basicBlocks do
    for dstBb in basicBlocks do
      let supposedFlow = (List.last srcBb, List.head dstBb)
      if controlFlows.Contains supposedFlow then
      // let targetInss = targetInstructions srcBb baseCfg
      // if Seq.contains (List.head dstBb) targetInss then
        basicBlockControlFlows.Add (srcBb, dstBb)
  let basicBlockEdges = Collections.Seq.map (fun (src, dst) -> QuickGraph.SEdge(src, dst)) basicBlockControlFlows
  QuickGraph.GraphExtensions.ToBidirectionalGraph basicBlockEdges

let basicBlockLabel<'TAddress when 'TAddress : unmanaged and 
                                   'TAddress : comparison> (basicBlock:BasicBlock<'TAddress>) =
  List.fold (+) "" <| List.map (fun (ins:Instruction<'TAddress>) -> 
                                Printf.sprintf "%s  %s\l" (hexStringOfValue<'TAddress> ins.Address) ins.Mnemonic) basicBlock

type BasicBlockDotEngine () =
  interface QuickGraph.Graphviz.IDotEngine with
    member this.Run (imgType:QuickGraph.Graphviz.Dot.GraphvizImageType, dotString:string, outputFilename:string) =
      System.IO.File.WriteAllText(outputFilename, dotString)
      outputFilename

let printBasicBlockCfg<'TAddress when 'TAddress : unmanaged and 
                                      'TAddress : comparison> (basicBlockCfg:BasicBlockCfg<'TAddress>) 
                                                              (outputFilename:string) =
  let graphvizFormat = QuickGraph.Graphviz.GraphvizAlgorithm(basicBlockCfg) 
  graphvizFormat.FormatVertex.Add(fun args ->
                                    let basicBlock = args.Vertex
                                    args.VertexFormatter.Style <- QuickGraph.Graphviz.Dot.GraphvizVertexStyle.Rounded
                                    args.VertexFormatter.Label <- basicBlockLabel basicBlock
                                    args.VertexFormatter.Font <- QuickGraph.Graphviz.Dot.GraphvizFont("Source Code Pro", 12.0f)
                                    args.VertexFormatter.Shape <- QuickGraph.Graphviz.Dot.GraphvizVertexShape.Box)
  graphvizFormat.Generate(new BasicBlockDotEngine(), outputFilename)

(*================================================================================================================*)

[<EntryPoint>]
let main argv = 
  if Array.length argv < 1 then
    Printf.printfn "please give a serialized trace file and/or an output file"
    0
  else
    let timer = new System.Diagnostics.Stopwatch()
    timer.Start()

    use traceFileReader = new System.IO.BinaryReader(System.IO.File.OpenRead(argv.[0]))
    let (addrIntSize, boolSize, threadIdSize) = parseTraceHeader traceFileReader
    Printf.printfn "data sizes: (ADDRINT: %d), (BOOL: %d), (THREADID: %d)" addrIntSize boolSize threadIdSize

    if addrIntSize = 8uy then
      // x86_64 (nothing now)
      Printf.printfn "x86_64"
    else
      Printf.printf "deserializing trace... "
      // let nativeTrace = deserializeTrace<uint32> traceFileReader
      let insCount, programControlFlow = deserializeTraceGeneric<uint32> traceFileReader
      Printf.printfn "done (%u parsed instructions, %u basic flows)." insCount programControlFlow.Count

      Printf.printf "constructing base control flow graph..."
      let baseCfg = constructBaseCfgFromControlFlows programControlFlow
      Printf.printfn "done (%u vertices)." baseCfg.VertexCount

      Printf.printf "building basic blocks..."
      let entryPoint = fst <| Seq.head programControlFlow
      let basicBlocks = buildBasicBlocks baseCfg entryPoint
      Printf.printfn "done (%u basic blocks)." basicBlocks.Count

      Printf.printf "constructing control flow graph..."
      let basicBlockCfg = constructBasicBlockCfg basicBlocks programControlFlow
      Printf.printf "done."

      let outputFilename =
        if Array.length argv > 1 then
          argv.[1]
        else
          System.IO.Path.ChangeExtension(argv.[0], ".dot")
      Printf.printf "write control flow graph to %s" outputFilename
      ignore <| printBasicBlockCfg basicBlockCfg outputFilename
      Printf.printfn "done."

      Printf.printfn "all done, elapsed time: %i ms" timer.ElapsedMilliseconds
    1