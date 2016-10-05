﻿type Instruction<'TAddress> = { Address : 'TAddress;
                                NextAddress : 'TAddress;
                                Mnemonic : string;
                                ThreadId : uint32 }

type NativeTrace<'TAddress> = ResizeArray<Instruction<'TAddress>>

type LocationMap<'TAddress when 'TAddress : comparison> = Map<'TAddress, Instruction<'TAddress> array>

type SmInstruction<'TAddress> = { Address : 'TAddress;
                                  InsIndex : int }

type Trace<'TAddress when 'TAddress : comparison> = ResizeArray<SmInstruction<'TAddress>>

//type BasicBlock<'TAddress when 'TAddress : comparison> = Trace<'TAddress>

type BasicBlock<'TAddress when 'TAddress : comparison> = SmInstruction<'TAddress> list

type BasicBlockCfg<'TAddress when 'TAddress : comparison> = QuickGraph.BidirectionalGraph<BasicBlock<'TAddress>, 
                                                                                          QuickGraph.SEdge<BasicBlock<'TAddress>>>

(*================================================================================================================*)

let getTraceLength<'TAddress> (traceFileReader : System.IO.BinaryReader) =
  let mutable traceLength = uint32 0
  match typeof<'TAddress> with
    | t when t = typeof<uint32> ->
      while (traceFileReader.BaseStream.Position <> traceFileReader.BaseStream.Length) do
        let insLength = traceFileReader.ReadUInt32 ()
        traceFileReader.BaseStream.Seek (int64 insLength, System.IO.SeekOrigin.Current) |> ignore
        traceLength <- traceLength + (uint32 1)

    | t when t = typeof<uint64> ->
      while (traceFileReader.BaseStream.Position <> traceFileReader.BaseStream.Length) do
        let insLength = traceFileReader.ReadUInt64 ()
        traceFileReader.BaseStream.Seek (int64 insLength, System.IO.SeekOrigin.Current) |> ignore
        traceLength <- traceLength + (uint32 1)

    | _ -> failwith "unknown type parameter" 
  traceLength

(*================================================================================================================*)

let deserializeOpcode<'TAddress when 'TAddress : unmanaged> (traceFileReader:System.IO.BinaryReader) =
  let opcodeSize =
    match typeof<'TAddress> with
      | t when t = typeof<uint32> -> int (traceFileReader.ReadUInt32 ())
      | t when t = typeof<uint64> -> int (traceFileReader.ReadUInt64 ())
      | _ -> failwith "unknown type parameter"
  let opcodeBuffer = traceFileReader.ReadBytes opcodeSize
  opcodeBuffer

(*================================================================================================================*)

let deserializeMnemonic<'TAddress when 'TAddress : unmanaged> (traceFileReader:System.IO.BinaryReader) =
  let mnemonicLength =
    match typeof<'TAddress> with
      | t when t = typeof<uint32> -> int (traceFileReader.ReadUInt32 ())
      | t when t = typeof<uint64> -> int (traceFileReader.ReadUInt64 ())
      | _ -> failwith "unknown type parameter"
  let mnemonicString = traceFileReader.ReadBytes mnemonicLength
  System.Text.Encoding.ASCII.GetString mnemonicString

(*================================================================================================================*)

let deserializeRegMap<'TAddress when 'TAddress : unmanaged> (traceFileReader:System.IO.BinaryReader) =
  let regMapLength =
    match typeof<'TAddress> with
      | t when t = typeof<uint32> -> int (traceFileReader.ReadUInt32 ())
      | t when t = typeof<uint64> -> int (traceFileReader.ReadUInt64 ())
      | _ -> failwith "unknown type parameter"
  let regMapBuffer = traceFileReader.ReadBytes regMapLength
  regMapBuffer

(*================================================================================================================*)

let deserializeMemMap<'TAddress when 'TAddress : unmanaged> (traceFileReader:System.IO.BinaryReader) =
  let memMapLength =
    match typeof<'TAddress> with
      | t when t = typeof<uint32> -> int (traceFileReader.ReadUInt32 ())
      | t when t = typeof<uint64> -> int (traceFileReader.ReadUInt64 ())
      | _ -> failwith "unknown type parameter"
  let memMapBuffer = traceFileReader.ReadBytes memMapLength
  memMapBuffer

(*================================================================================================================*)

let deserializeTrace<'TAddress  when 'TAddress : unmanaged> (traceFileReader:System.IO.BinaryReader) =
  let trace = ResizeArray<_>()
  while (traceFileReader.BaseStream.Position <> traceFileReader.BaseStream.Length) do
    let serializedLength =
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
    let mnemonicStr = deserializeMnemonic<'TAddress> traceFileReader
    deserializeRegMap<'TAddress> traceFileReader |> ignore
    deserializeRegMap<'TAddress> traceFileReader |> ignore
    deserializeMemMap<'TAddress> traceFileReader |> ignore
    deserializeMemMap<'TAddress> traceFileReader |> ignore
    let threadId = traceFileReader.ReadUInt32 ()
    trace.Add { Address = address;
                NextAddress = nextAddress;
                Mnemonic = mnemonicStr;
                ThreadId = threadId }
  trace

(*================================================================================================================*)

let getLocationMap<'TAddress when 'TAddress : unmanaged and
                                  'TAddress : comparison> (nativeTrace:NativeTrace<'TAddress>) =
  let mutable locationMap = Map.empty
  for instruction in nativeTrace do
    if locationMap.ContainsKey instruction.Address then
      let locIns = Map.find instruction.Address locationMap
      if not (Array.exists (fun (ins:Instruction<'TAddress>) -> 
                              ins.Mnemonic = instruction.Mnemonic) locIns) then
        let newLocIns = Array.append locIns [|instruction|]
        Map.remove instruction.Address locationMap |> 
        Map.add instruction.Address newLocIns |> ignore
  locationMap

(*================================================================================================================*)

let convertNativeTraceToTrace<'TAddress when 'TAddress : unmanaged and
                                             'TAddress : comparison> (nativeTrace:NativeTrace<'TAddress>) 
                                                                     (locationMap:LocationMap<'TAddress>) =
  let trace = new Trace<'TAddress>()
  for instruction in nativeTrace do
    let locIns = Map.find instruction.Address locationMap
    let insIndex = Array.findIndex (fun (ins:Instruction<'TAddress>) -> ins.Mnemonic = instruction.Mnemonic) locIns
    let loc = { Address = instruction.Address; InsIndex = insIndex }
    trace.Add loc
  trace

(*================================================================================================================*)

let getDistinguishedTrace<'TAddress when 'TAddress : unmanaged and 
                                         'TAddress : comparison> (trace:Trace<'TAddress>) =
  let distinguishedSmInss = new Trace<'TAddress>()
  for smIns in trace do
    if not (distinguishedSmInss.Contains smIns) then
      distinguishedSmInss.Add smIns
  distinguishedSmInss

(*================================================================================================================*)

let getBranchSmInstructions<'TAddress when 'TAddress : unmanaged and 
                                           'TAddress : comparison> (distinguishedInss:Trace<'TAddress>) 
                                                                   (trace:Trace<'TAddress>) =
  let goAfterMap = new System.Collections.Generic.Dictionary<SmInstruction<'TAddress>, SmInstruction<'TAddress> list>()
  for ins in distinguishedInss do
    goAfterMap.Add (ins, List.empty) |> ignore
  if trace.Count > 1 then
    for i = 0 to trace.Count - 2 do
      let currentFollowingInss = goAfterMap.[trace.[i]]
      let newFollowingIns = trace.[i + 1]
      if not (List.contains newFollowingIns currentFollowingInss) then
        let newFollowingInss = newFollowingIns :: currentFollowingInss
        goAfterMap.Remove(trace.[i]) |> ignore
        goAfterMap.Add(trace.[i], newFollowingInss)
  let branchInss = new System.Collections.Generic.List<SmInstruction<'TAddress>>()
  for entry in goAfterMap do
    if List.length entry.Value > 1 then
      branchInss.Add entry.Key
  List.ofSeq branchInss

(*================================================================================================================*)

let getTargetSmInstructions<'TAddress when 'TAddress : unmanaged and
                                           'TAddress : comparison> (distinguishedInss:Trace<'TAddress>) 
                                                                   (trace:Trace<'TAddress>) =
//  let insGoBefore = new Map<SmInstruction<'TAddress>, SmInstruction<'TAddress> list>()
  let goBeforeMap = new System.Collections.Generic.Dictionary<SmInstruction<'TAddress>, SmInstruction<'TAddress> list>()
  for ins in distinguishedInss do
    goBeforeMap.Add (ins, List.empty) |> ignore
  if trace.Count > 1 then
    for i = 1 to trace.Count - 1 do
      let currentBeforeInss = goBeforeMap.[trace.[i]]
      let newBeforeIns = trace.[i - 1]
      if not (List.contains newBeforeIns currentBeforeInss) then
        let newBeforeInss = newBeforeIns :: currentBeforeInss
        goBeforeMap.Remove(trace.[i]) |> ignore
        goBeforeMap.Add(trace.[i], newBeforeInss)
  let targets = new System.Collections.Generic.List<SmInstruction<'TAddress>>()
  for entry in goBeforeMap do
    if List.length entry.Value > 1 then
      targets.Add entry.Key
  List.ofSeq targets

(*================================================================================================================*)

let getLeaderSmInstruction<'TAddress when 'TAddress : unmanaged and 
                                          'TAddress : comparison> (branchInstructions:SmInstruction<'TAddress> list) 
                                                                  (targetInstructions:SmInstruction<'TAddress> list)
                                                                  (trace:Trace<'TAddress>) =
  if not (Seq.isEmpty trace) then
    let leaderInss = new System.Collections.Generic.List<SmInstruction<'TAddress>>(targetInstructions)
    leaderInss.Add trace.[0]
    if trace.Count > 1 then
      for i = 0 to trace.Count - 2 do
        if List.contains trace.[i] branchInstructions then
          leaderInss.Add trace.[i + 1]
    Seq.distinct leaderInss |> List.ofSeq
  else
    []

//  let leaderInss = new System.Collections.Generic.List<SmInstruction<'TAddress>>(targetInstructions)
//  if not (Seq.isEmpty trace) then
//    leaderInss.Add trace.[0]
////    if not (leaderInss.Contains trace.[0]) then
////      leaderInss.Add trace.[0]
//  if trace.Count > 1 then
//    for i = 0 to trace.Count - 2 do
//      if leaderInss.Contains trace.[i] then
//        if not (leaderInss.Contains trace.[i + 1]) then
//          leaderInss.Add trace.[i + 1]
//  List.ofSeq leaderInss

(*================================================================================================================*)

// see http://www.cis.upenn.edu/~cis570/slides/lecture03.pdf
let buildBasicBlocks<'TAddress when 'TAddress : unmanaged and 
                                    'TAddress : comparison> (leaderInstructions:SmInstruction<'TAddress> list) 
                                                            (distinguishedTrace:Trace<'TAddress>) =
  let basicBlocks = new System.Collections.Generic.List<BasicBlock<'TAddress>>()
  for leaderIns in leaderInstructions do
    let mutable newBasicBlock = [leaderIns]
    let mutable insIdx = distinguishedTrace.IndexOf(leaderIns)
    if (insIdx < distinguishedTrace.Count - 1) then
      insIdx <- insIdx + 1
      while (insIdx < distinguishedTrace.Count) && 
            not (List.contains distinguishedTrace.[insIdx] leaderInstructions) do
        newBasicBlock <- distinguishedTrace.[insIdx] :: newBasicBlock
        insIdx <- insIdx + 1
      newBasicBlock <- List.rev newBasicBlock
      basicBlocks.Add newBasicBlock
  Seq.toList basicBlocks

(*================================================================================================================*)

let constructControlFlowGraph<'TAddress when 'TAddress : unmanaged and 
                                             'TAddress : comparison> (trace:Trace<'TAddress>) 
                                                                     (basicBlocks:BasicBlock<'TAddress> list) =
  let connections = new System.Collections.Generic.List<SmInstruction<'TAddress> * SmInstruction<'TAddress>>()
  let basicBlockConnections = new System.Collections.Generic.List<BasicBlock<'TAddress> * BasicBlock<'TAddress>>()
  if trace.Count > 1 then
    for insIdx = 0 to trace.Count - 2 do
      if not (connections.Contains (trace.[insIdx], trace.[insIdx + 1])) then
        connections.Add (trace.[insIdx], trace.[insIdx + 1])
  for srcBb in basicBlocks do
    for dstBb in basicBlocks do
      let srcIns = Seq.last srcBb
      let dstIns = Seq.head dstBb
      if connections.Contains (srcIns, dstIns) then
        basicBlockConnections.Add (srcBb, dstBb)
  let basicBlockEdges = Seq.map (fun (src, dst) -> QuickGraph.SEdge(src, dst)) (Seq.distinct basicBlockConnections)
  QuickGraph.GraphExtensions.ToBidirectionalGraph basicBlockEdges

(*================================================================================================================*)

let hexStringOfValue<'TAddress when 'TAddress : unmanaged> (insAddr:'TAddress) =
  match box insAddr with
    | :? uint32 as uint32Addr -> Printf.sprintf "0x%x" uint32Addr
    | :? uint64 as uint64Addr -> Printf.sprintf "0x%x" uint64Addr
    | _ -> failwith "unknown type parameter"

let basicBlockLabel<'TAddress when 'TAddress : unmanaged and 
                                   'TAddress : comparison> (locationMap:LocationMap<'TAddress>) 
                                                           (basicBlock:BasicBlock<'TAddress>) =
 List.fold (+) "" <| 
 List.map (fun (ins:SmInstruction<'TAddress>) -> 
             Printf.sprintf "%s  %s\l" (hexStringOfValue<'TAddress> ins.Address) 
                                       ((locationMap.[ins.Address]).[ins.InsIndex]).Mnemonic) basicBlock
                                                                            
type dotEngine () = 
  interface QuickGraph.Graphviz.IDotEngine with
    member this.Run (imgType:QuickGraph.Graphviz.Dot.GraphvizImageType, dotString:string, outputFilename:string) =
      System.IO.File.WriteAllText(outputFilename, dotString)
      outputFilename

let printControlFlowGraph<'TAddress when 'TAddress : comparison and 
                                         'TAddress : unmanaged> (distinguisedTrace:Trace<'TAddress>) 
                                                                (locationMap:LocationMap<'TAddress>)
                                                                (bbCfg:BasicBlockCfg<'TAddress>)
                                                                (outputFilename:string) =
  let graphvizFormat = QuickGraph.Graphviz.GraphvizAlgorithm(bbCfg)
  graphvizFormat.FormatVertex.Add(fun args -> 
                                    let basicBlock = args.Vertex
                                    args.VertexFormatter.Style <- QuickGraph.Graphviz.Dot.GraphvizVertexStyle.Rounded
                                    args.VertexFormatter.Label <- basicBlockLabel locationMap basicBlock
                                    args.VertexFormatter.Font <- QuickGraph.Graphviz.Dot.GraphvizFont("Source Code Pro", 12.0f)
                                    args.VertexFormatter.Shape <- QuickGraph.Graphviz.Dot.GraphvizVertexShape.Box)
  


//  let basicBlocks = new System.Collections.Generic.List<BasicBlock<'TAddress>>()
//  let mutable insIndex = 0
//  let mutable newBasicBlock = List.empty
//  while insIndex < distinguishedTrace.Count do
//    newBasicBlock <- List.empty
//    if List.contains distinguishedTrace.[insIndex] leaderInstructions then
//      newBasicBlock <- [distinguishedTrace.[insIndex]]

      

(*================================================================================================================*)

//let   

// see http://www.cis.upenn.edu/~cis570/slides/lecture03.pdf
//let buildBasicBlocks<'TAddress when 'TAddress : unmanaged and
//                                    'TAddress : comparison> (trace:Trace<'TAddress>) =
  

[<EntryPoint>]
let main argv = 
    printfn "%A" argv
     0 // return an integer exit code
