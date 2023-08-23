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

record BasicBlock = 
    id :: BasicBlockId
    entry :: string
    exit :: string
    pcodes :: "PcodeId list"

record Pcode =
    id :: PcodeId
    operation :: PcodeOp
    parent :: BasicBlockId
    inputs :: "Varnode list"
    pcodeOutput :: "Varnode option"

record Symbol =
    id :: SymbolId
    dataType :: string
    length :: int
    isPointer :: bool
    representative :: "Varnode option"

record BasicBlockControlFlow = 
    preds :: "BasicBlockId set"
    succs :: "BasicBlockId set"

record PcodeControlFlow = 
    preds :: "PcodeId set"
    sucss :: "PcodeId set"

record ControlFlowGraph =
    basicblocks :: "(BasicBlockId, BasicBlockControlFlow) rbt"
    pcodes :: "(PcodeId, PcodeControlFlow) rbt"

record Function =
    name :: string
    entry :: string
    exit :: string
    basicblocks :: "(BasicBlockId, BasicBlock) rbt"
    pcodes :: "(PcodeId, Pcode) rbt"
    varnodes :: "Varnode list"
    symbols :: "(SymbolId, Symbol) rbt"
    cfg :: ControlFlowGraph

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

end 