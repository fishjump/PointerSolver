theory SolverTypes
    imports Main
            "HOL-Library.Finite_Map"
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
    basicblocks :: "(BasicBlockId, BasicBlockControlFlow) map"
    pcodes :: "(PcodeId, PcodeControlFlow) map"

record Function =
    name :: string
    entry :: string
    exit :: string
    basicblocks :: "(BasicBlockId, BasicBlock) map"
    pcodes :: "(PcodeId, Pcode) map"
    varnodes :: "Varnode list"
    symbols :: "(SymbolId, Symbol) map"
    cfg :: ControlFlowGraph

definition mySet :: "char list set" where
  "mySet = {''1'', ''2'', ''3''}"

(* instantiation string :: linorder
begin

end *)

value "sorted_list_of_set mySet"



value "''1'' @ ''2''"


end 