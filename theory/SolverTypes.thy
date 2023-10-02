theory SolverTypes
    imports Main
            "HOL-Library.RBT"
            "StringLinorder"
begin

type_synonym BasicBlockId = string
type_synonym PcodeId = string
type_synonym Varnode = string
type_synonym SymbolId = string

datatype PcodeOp = INT_EQUAL 
  | INT_NOTEQUAL
  | INT_LESS
  | INT_SLESS
  | INT_LESSEQUAL
  | INT_SLESSEQUAL
  | INT_CARRY
  | INT_SCARRY
  | INT_SBORROW
  | INT_ADD 
  | INT_SUB
  | INT_XOR
  | INT_AND
  | INT_OR
  | INT_LEFT
  | INT_RIGHT
  | INT_SRIGHT
  | INT_MULT
  | INT_DIV
  | INT_REM
  | INT_SDIV
  | INT_SREM
  | INT_ZEXT 
  | INT_SEXT
  | INT_2COMP
  | INT_NEGATE
  | FLOAT_EQUAL 
  | FLOAT_NOT_EQUAL
  | FLOAT_LESS
  | FLOAT_LESS_EQUAL
  | FLOAT_ADD
  | FLOAT_SUB
  | FLOAT_MULT
  | FLOAT_DIV
  | FLOAT_NEG
  | FLOAT_ABS
  | FLOAT_SQRT
  | FLOAT_CEIL
  | FLOAT_FLOOR
  | FLOAT_ROUND
  | FLOAT_NAN
  | BOOL_XOR
  | BOOL_AND
  | BOOL_OR
  | BOOL_NEGATE
  | COPY
  | LOAD
  | STORE
  | BRANCH
  | CBRANCH
  | BRANCHIND
  | CALL
  | CALLIND
  | RETURN
  | PIECE
  | SUBPIECE
  | INT2FLOAT
  | FLOAT2FLOAT
  | TRUNC
  | PTRADD
  | PTRSUB
  | POPCOUNT
  | MULTIEQUAL
  | CAST
  | INDIRECT
  | UNKNOWN

datatype BasicBlock = BasicBlock BasicBlockId string string "PcodeId list"

(* record BasicBlock = 
    id :: BasicBlockId
    entry :: string
    exit :: string
    pcodes :: "PcodeId list" *)

datatype Pcode = Pcode PcodeId PcodeOp BasicBlockId "Varnode list" "Varnode option"

fun Pcode_Id :: "Pcode \<Rightarrow> PcodeId" where
    "Pcode_Id (Pcode pcodeId _ _ _ _) = pcodeId"

fun Pcode_Inputs :: "Pcode \<Rightarrow> Varnode list" where
    "Pcode_Inputs (Pcode _ _ _ inputs _) = inputs"

fun Pcode_Output :: "Pcode \<Rightarrow> Varnode option" where
    "Pcode_Output (Pcode _ _ _ _ output) = output"

(* record Pcode =
    id :: PcodeId
    operation :: PcodeOp
    parent :: BasicBlockId
    inputs :: "Varnode list"
    pcodeOutput :: "Varnode option" *)

datatype Symbol = Symbol SymbolId string int bool "Varnode option"

(* record Symbol =
    id :: SymbolId
    dataType :: string
    length :: int
    isPointer :: bool
    representative :: "Varnode option" *)

datatype BasicBlockControlFlow = BasicBlockControlFlow "BasicBlockId set" "BasicBlockId set"

(* record BasicBlockControlFlow = 
    preds :: "BasicBlockId set"
    succs :: "BasicBlockId set" *)

datatype PcodeControlFlow = PcodeControlFlow "PcodeId set" "PcodeId set"

fun PcodeControlFlow_Preds :: "PcodeControlFlow \<Rightarrow> PcodeId set" where
    "PcodeControlFlow_Preds (PcodeControlFlow preds _) = preds"

(* record PcodeControlFlow = 
    preds :: "PcodeId set"
    sucss :: "PcodeId set" *)

datatype ControlFlowGraph = ControlFlowGraph "(BasicBlockId, BasicBlockControlFlow) rbt" "(PcodeId, PcodeControlFlow) rbt"

fun ControlFlowGraph_Pcodes :: "ControlFlowGraph \<Rightarrow> (PcodeId, PcodeControlFlow) rbt" where
    "ControlFlowGraph_Pcodes (ControlFlowGraph _ pcodes) = pcodes"

(* record ControlFlowGraph =
    basicblocks :: "(BasicBlockId, BasicBlockControlFlow) rbt"
    pcodes :: "(PcodeId, PcodeControlFlow) rbt" *)

datatype Function = Function string string string "(BasicBlockId, BasicBlock) rbt" "(PcodeId, Pcode) rbt" "Varnode list" "(SymbolId, Symbol) rbt" ControlFlowGraph

fun Function_Pcodes :: "Function \<Rightarrow> (PcodeId, Pcode) rbt" where
    "Function_Pcodes (Function _ _ _ _ pcodes _ _ _) = pcodes"

fun Function_Cfg :: "Function \<Rightarrow> ControlFlowGraph" where
    "Function_Cfg (Function _ _ _ _ _ _ _ cfg) = cfg"

(* record Function =
    name :: string
    entry :: string
    exit :: string
    basicblocks :: "(BasicBlockId, BasicBlock) rbt"
    pcodes :: "(PcodeId, Pcode) rbt"
    varnodes :: "Varnode list"
    symbols :: "(SymbolId, Symbol) rbt"
    cfg :: ControlFlowGraph *)

datatype Type = 
    Integer | 
    Bool | 
    Float | 
    Pointer | 
    PointerOfPointer | 
    Unknown

datatype Event = 
    ToInt | 
    ToBool | 
    ToFloat | 
    ToPointer | 
    ToPointerOfPointer | 
    Idle

fun transition :: "Event \<Rightarrow> Type \<Rightarrow> Type" where
    "transition ToInt Unknown = Integer" |
    "transition ToBool Unknown = Bool" |
    "transition ToFloat Unknown = Float" |
    "transition ToPointer Integer = Pointer" |
    "transition ToPointerOfPointer Pointer = PointerOfPointer" |
    "transition _ t = t"


lemma "transition ToInt Unknown = Integer" by auto
lemma "transition ToBool Unknown = Bool" by auto
lemma "transition ToFloat Unknown = Float" by auto
lemma "transition ToPointer Integer = Pointer" by auto
lemma "transition ToPointerOfPointer Pointer = PointerOfPointer" by auto
lemma "\<forall> e t. ((e \<noteq> ToInt \<and> t \<noteq> Unknown) \<and>
            (e \<noteq> ToBool \<and> t \<noteq> Unknown) \<and>
            (e \<noteq> ToFloat \<and> t \<noteq> Unknown) \<and>
            (e \<noteq> ToPointer \<and> t \<noteq> Integer) \<and>
            (e \<noteq> ToPointerOfPointer \<and> t \<noteq> Pointer)) \<longrightarrow> transition e t = t"
proof (intro conjI allI impI)
    fix e t
    assume "(e \<noteq> ToInt \<and> t \<noteq> Unknown) \<and>
            (e \<noteq> ToBool \<and> t \<noteq> Unknown) \<and>
            (e \<noteq> ToFloat \<and> t \<noteq> Unknown) \<and>
            (e \<noteq> ToPointer \<and> t \<noteq> Integer) \<and>
            (e \<noteq> ToPointerOfPointer \<and> t \<noteq> Pointer)"
    then show "transition e t = t" by (cases e) auto
qed

fun toSome :: "Type \<Rightarrow> Event" where
    "toSome Integer = ToInt" |
    "toSome Bool = ToBool" |
    "toSome Float = ToFloat" |
    "toSome Pointer = ToPointer" |
    "toSome PointerOfPointer = ToPointerOfPointer" |
    "toSome _ = Idle"

lemma "toSome Integer = ToInt" by auto
lemma "toSome Bool = ToBool" by auto
lemma "toSome Float = ToFloat" by auto
lemma "toSome Pointer = ToPointer" by auto
lemma "toSome PointerOfPointer = ToPointerOfPointer" by auto
lemma "\<forall> t. (t \<noteq> Integer \<and> 
            t \<noteq> Bool \<and>
            t \<noteq> Float \<and>
            t \<noteq> Pointer \<and>
            t \<noteq> PointerOfPointer) 
        \<longrightarrow> toSome t = Idle"
proof (intro allI impI)
    fix t
    assume "t \<noteq> Integer \<and> 
            t \<noteq> Bool \<and>
            t \<noteq> Float \<and>
            t \<noteq> Pointer \<and>
            t \<noteq> PointerOfPointer"
    then show "toSome t = Idle" by (cases t) auto
qed

type_synonym SolverContext = "(Varnode, Type) rbt"
type_synonym UDChainContext = "(PcodeId \<times> Varnode, PcodeId set) rbt"

class deducer =
    fixes deduceStage1 :: "'a \<Rightarrow> SolverContext \<Rightarrow> Pcode \<Rightarrow> SolverContext"
    fixes deduceStage2 :: "'a \<Rightarrow> SolverContext \<Rightarrow> Pcode \<Rightarrow> SolverContext"
    fixes deduceStage3 :: "'a \<Rightarrow> SolverContext \<Rightarrow> Pcode \<Rightarrow> SolverContext"

definition default_deduce :: "'a \<Rightarrow> SolverContext \<Rightarrow> Pcode \<Rightarrow> SolverContext" where
    "default_deduce _ ctx _ = ctx"

end 