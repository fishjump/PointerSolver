{-# LANGUAGE DataKinds #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE TypeFamilies #-}

module PointerSolver.Solver.PcodeDeducer.MapPcodeOpToDeducer where

import PointerSolver.Solver.Context (Context)
import PointerSolver.Solver.PcodeDeducer.BoolBinOp (BoolBinOp (BoolBinOp))
import PointerSolver.Solver.PcodeDeducer.BoolUnaryOp (BoolUnaryOp (BoolUnaryOp))
import PointerSolver.Solver.PcodeDeducer.CBranch (CBranch (CBranch))
import PointerSolver.Solver.PcodeDeducer.Cast (Cast (Cast))
import PointerSolver.Solver.PcodeDeducer.Copy (Copy (Copy))
import PointerSolver.Solver.PcodeDeducer.Float2Float (Float2Float (Float2Float))
import PointerSolver.Solver.PcodeDeducer.FloatBinOp (FloatBinOp (FloatBinOp))
import PointerSolver.Solver.PcodeDeducer.FloatLogicOp (FloatLogicOp (FloatLogicOp))
import PointerSolver.Solver.PcodeDeducer.FloatUnaryOp (FloatUnaryOp (FloatUnaryOp))
import PointerSolver.Solver.PcodeDeducer.Indirect (Indirect (Indirect))
import PointerSolver.Solver.PcodeDeducer.Int2Float (Int2Float (Int2Float))
import PointerSolver.Solver.PcodeDeducer.IntBinaryOp (IntBinaryOp (IntBinaryOp))
import PointerSolver.Solver.PcodeDeducer.IntLogicOp (IntLogicOp (IntLogicOp))
import PointerSolver.Solver.PcodeDeducer.IntUnaryOp (IntUnaryOp (IntUnaryOp))
import PointerSolver.Solver.PcodeDeducer.Jump (Jump (Jump))
import PointerSolver.Solver.PcodeDeducer.Load (Load (Load))
import PointerSolver.Solver.PcodeDeducer.MultiEqual (MultiEqual (MultiEqual))
import PointerSolver.Solver.PcodeDeducer.PcodeDeducer (Deducer (deduceStage1, deduceStage2, deduceStage3))
import PointerSolver.Solver.PcodeDeducer.Piece (Piece (Piece))
import PointerSolver.Solver.PcodeDeducer.PopCount (PopCount (PopCount))
import PointerSolver.Solver.PcodeDeducer.PtrAdd (PtrAdd (PtrAdd))
import PointerSolver.Solver.PcodeDeducer.PtrSub (PtrSub (PtrSub))
import PointerSolver.Solver.PcodeDeducer.Store (Store (Store))
import PointerSolver.Solver.PcodeDeducer.SubPiece (SubPiece (SubPiece))
import PointerSolver.Solver.PcodeDeducer.Trunc (Trunc (Trunc))
import PointerSolver.Solver.PcodeDeducer.UnknownOp (UnknownOp (UnknownOp))
import PointerSolver.Type.Pcode.Pcode (Pcode)
import PointerSolver.Type.PcodeOp.PcodeOp (PcodeOp (..))

stage1Deducer :: PcodeOp -> Context -> Pcode -> Context
-- Int Logic Op --
stage1Deducer INT_EQUAL = deduceStage1 IntLogicOp
stage1Deducer INT_NOTEQUAL = deduceStage1 IntLogicOp
stage1Deducer INT_LESS = deduceStage1 IntLogicOp
stage1Deducer INT_SLESS = deduceStage1 IntLogicOp
stage1Deducer INT_LESSEQUAL = deduceStage1 IntLogicOp
stage1Deducer INT_SLESSEQUAL = deduceStage1 IntLogicOp
stage1Deducer INT_CARRY = deduceStage1 IntLogicOp
stage1Deducer INT_SCARRY = deduceStage1 IntLogicOp
stage1Deducer INT_SBORROW = deduceStage1 IntLogicOp
-- Int Bin Op --
stage1Deducer INT_ADD = deduceStage1 IntBinaryOp
stage1Deducer INT_SUB = deduceStage1 IntBinaryOp
stage1Deducer INT_XOR = deduceStage1 IntBinaryOp
stage1Deducer INT_AND = deduceStage1 IntBinaryOp
stage1Deducer INT_OR = deduceStage1 IntBinaryOp
stage1Deducer INT_LEFT = deduceStage1 IntBinaryOp
stage1Deducer INT_RIGHT = deduceStage1 IntBinaryOp
stage1Deducer INT_SRIGHT = deduceStage1 IntBinaryOp
stage1Deducer INT_MULT = deduceStage1 IntBinaryOp
stage1Deducer INT_DIV = deduceStage1 IntBinaryOp
stage1Deducer INT_REM = deduceStage1 IntBinaryOp
stage1Deducer INT_SDIV = deduceStage1 IntBinaryOp
stage1Deducer INT_SREM = deduceStage1 IntBinaryOp
-- Int Unary Op --
stage1Deducer INT_ZEXT = deduceStage1 IntUnaryOp
stage1Deducer INT_SEXT = deduceStage1 IntUnaryOp
stage1Deducer INT_2COMP = deduceStage1 IntUnaryOp
stage1Deducer INT_NEGATE = deduceStage1 IntUnaryOp
-- Float Logic Op --
stage1Deducer FLOAT_EQUAL = deduceStage1 FloatLogicOp
stage1Deducer FLOAT_NOT_EQUAL = deduceStage1 FloatLogicOp
stage1Deducer FLOAT_LESS = deduceStage1 FloatLogicOp
stage1Deducer FLOAT_LESS_EQUAL = deduceStage1 FloatLogicOp
-- Float Bin Op --
stage1Deducer FLOAT_ADD = deduceStage1 FloatBinOp
stage1Deducer FLOAT_SUB = deduceStage1 FloatBinOp
stage1Deducer FLOAT_MULT = deduceStage1 FloatBinOp
stage1Deducer FLOAT_DIV = deduceStage1 FloatBinOp
-- Float Unary Op --
stage1Deducer FLOAT_NEG = deduceStage1 FloatUnaryOp
stage1Deducer FLOAT_ABS = deduceStage1 FloatUnaryOp
stage1Deducer FLOAT_SQRT = deduceStage1 FloatUnaryOp
stage1Deducer FLOAT_CEIL = deduceStage1 FloatUnaryOp
stage1Deducer FLOAT_FLOOR = deduceStage1 FloatUnaryOp
stage1Deducer FLOAT_ROUND = deduceStage1 FloatUnaryOp
stage1Deducer FLOAT_NAN = deduceStage1 FloatUnaryOp
-- Bool Bin Op --
stage1Deducer BOOL_XOR = deduceStage1 BoolBinOp
stage1Deducer BOOL_AND = deduceStage1 BoolBinOp
stage1Deducer BOOL_OR = deduceStage1 BoolBinOp
-- Bool Unary Op --
stage1Deducer BOOL_NEGATE = deduceStage1 BoolUnaryOp
-- Others --
stage1Deducer COPY = deduceStage1 Copy
stage1Deducer LOAD = deduceStage1 Load
stage1Deducer STORE = deduceStage1 Store
-- JUMP --
stage1Deducer BRANCH = deduceStage1 Jump
stage1Deducer BRANCHIND = deduceStage1 Jump
stage1Deducer CALL = deduceStage1 Jump
stage1Deducer CALLIND = deduceStage1 Jump
stage1Deducer RETURN = deduceStage1 Jump
-- Others --
stage1Deducer CBRANCH = deduceStage1 CBranch
stage1Deducer PIECE = deduceStage1 Piece
stage1Deducer SUBPIECE = deduceStage1 SubPiece
stage1Deducer INT2FLOAT = deduceStage1 Int2Float
stage1Deducer FLOAT2FLOAT = deduceStage1 Float2Float
stage1Deducer TRUNC = deduceStage1 Trunc
stage1Deducer PTRADD = deduceStage1 PtrAdd
stage1Deducer PTRSUB = deduceStage1 PtrSub
-- Not Implemented --
stage1Deducer POPCOUNT = deduceStage1 PopCount
stage1Deducer MULTIEQUAL = deduceStage1 MultiEqual
stage1Deducer CAST = deduceStage1 Cast
stage1Deducer INDIRECT = deduceStage1 Indirect
stage1Deducer UNKNOWN = deduceStage1 UnknownOp

stage2Deducer :: PcodeOp -> Context -> Pcode -> Context
-- Int Logic Op --
stage2Deducer INT_EQUAL = deduceStage2 IntLogicOp
stage2Deducer INT_NOTEQUAL = deduceStage2 IntLogicOp
stage2Deducer INT_LESS = deduceStage2 IntLogicOp
stage2Deducer INT_SLESS = deduceStage2 IntLogicOp
stage2Deducer INT_LESSEQUAL = deduceStage2 IntLogicOp
stage2Deducer INT_SLESSEQUAL = deduceStage2 IntLogicOp
stage2Deducer INT_CARRY = deduceStage2 IntLogicOp
stage2Deducer INT_SCARRY = deduceStage2 IntLogicOp
stage2Deducer INT_SBORROW = deduceStage2 IntLogicOp
-- Int Bin Op --
stage2Deducer INT_ADD = deduceStage2 IntBinaryOp
stage2Deducer INT_SUB = deduceStage2 IntBinaryOp
stage2Deducer INT_XOR = deduceStage2 IntBinaryOp
stage2Deducer INT_AND = deduceStage2 IntBinaryOp
stage2Deducer INT_OR = deduceStage2 IntBinaryOp
stage2Deducer INT_LEFT = deduceStage2 IntBinaryOp
stage2Deducer INT_RIGHT = deduceStage2 IntBinaryOp
stage2Deducer INT_SRIGHT = deduceStage2 IntBinaryOp
stage2Deducer INT_MULT = deduceStage2 IntBinaryOp
stage2Deducer INT_DIV = deduceStage2 IntBinaryOp
stage2Deducer INT_REM = deduceStage2 IntBinaryOp
stage2Deducer INT_SDIV = deduceStage2 IntBinaryOp
stage2Deducer INT_SREM = deduceStage2 IntBinaryOp
-- Int Unary Op --
stage2Deducer INT_ZEXT = deduceStage2 IntUnaryOp
stage2Deducer INT_SEXT = deduceStage2 IntUnaryOp
stage2Deducer INT_2COMP = deduceStage2 IntUnaryOp
stage2Deducer INT_NEGATE = deduceStage2 IntUnaryOp
-- Float Logic Op --
stage2Deducer FLOAT_EQUAL = deduceStage2 FloatLogicOp
stage2Deducer FLOAT_NOT_EQUAL = deduceStage2 FloatLogicOp
stage2Deducer FLOAT_LESS = deduceStage2 FloatLogicOp
stage2Deducer FLOAT_LESS_EQUAL = deduceStage2 FloatLogicOp
-- Float Bin Op --
stage2Deducer FLOAT_ADD = deduceStage2 FloatBinOp
stage2Deducer FLOAT_SUB = deduceStage2 FloatBinOp
stage2Deducer FLOAT_MULT = deduceStage2 FloatBinOp
stage2Deducer FLOAT_DIV = deduceStage2 FloatBinOp
-- Float Unary Op --
stage2Deducer FLOAT_NEG = deduceStage2 FloatUnaryOp
stage2Deducer FLOAT_ABS = deduceStage2 FloatUnaryOp
stage2Deducer FLOAT_SQRT = deduceStage2 FloatUnaryOp
stage2Deducer FLOAT_CEIL = deduceStage2 FloatUnaryOp
stage2Deducer FLOAT_FLOOR = deduceStage2 FloatUnaryOp
stage2Deducer FLOAT_ROUND = deduceStage2 FloatUnaryOp
stage2Deducer FLOAT_NAN = deduceStage2 FloatUnaryOp
-- Bool Bin Op --
stage2Deducer BOOL_XOR = deduceStage2 BoolBinOp
stage2Deducer BOOL_AND = deduceStage2 BoolBinOp
stage2Deducer BOOL_OR = deduceStage2 BoolBinOp
-- Bool Unary Op --
stage2Deducer BOOL_NEGATE = deduceStage2 BoolUnaryOp
-- Others --
stage2Deducer COPY = deduceStage2 Copy
stage2Deducer LOAD = deduceStage2 Load
stage2Deducer STORE = deduceStage2 Store
-- JUMP --
stage2Deducer BRANCH = deduceStage2 Jump
stage2Deducer BRANCHIND = deduceStage2 Jump
stage2Deducer CALL = deduceStage2 Jump
stage2Deducer CALLIND = deduceStage2 Jump
stage2Deducer RETURN = deduceStage2 Jump
-- Others --
stage2Deducer CBRANCH = deduceStage2 CBranch
stage2Deducer PIECE = deduceStage2 Piece
stage2Deducer SUBPIECE = deduceStage2 SubPiece
stage2Deducer INT2FLOAT = deduceStage2 Int2Float
stage2Deducer FLOAT2FLOAT = deduceStage2 Float2Float
stage2Deducer TRUNC = deduceStage2 Trunc
stage2Deducer PTRADD = deduceStage2 PtrAdd
stage2Deducer PTRSUB = deduceStage2 PtrSub
-- Not Implemented --
stage2Deducer POPCOUNT = deduceStage2 PopCount
stage2Deducer MULTIEQUAL = deduceStage2 MultiEqual
stage2Deducer CAST = deduceStage2 Cast
stage2Deducer INDIRECT = deduceStage2 Indirect
stage2Deducer UNKNOWN = deduceStage2 UnknownOp

stage3Deducer :: PcodeOp -> Context -> Pcode -> Context
-- Int Logic Op --
stage3Deducer INT_EQUAL = deduceStage3 IntLogicOp
stage3Deducer INT_NOTEQUAL = deduceStage3 IntLogicOp
stage3Deducer INT_LESS = deduceStage3 IntLogicOp
stage3Deducer INT_SLESS = deduceStage3 IntLogicOp
stage3Deducer INT_LESSEQUAL = deduceStage3 IntLogicOp
stage3Deducer INT_SLESSEQUAL = deduceStage3 IntLogicOp
stage3Deducer INT_CARRY = deduceStage3 IntLogicOp
stage3Deducer INT_SCARRY = deduceStage3 IntLogicOp
stage3Deducer INT_SBORROW = deduceStage3 IntLogicOp
-- Int Bin Op --
stage3Deducer INT_ADD = deduceStage3 IntBinaryOp
stage3Deducer INT_SUB = deduceStage3 IntBinaryOp
stage3Deducer INT_XOR = deduceStage3 IntBinaryOp
stage3Deducer INT_AND = deduceStage3 IntBinaryOp
stage3Deducer INT_OR = deduceStage3 IntBinaryOp
stage3Deducer INT_LEFT = deduceStage3 IntBinaryOp
stage3Deducer INT_RIGHT = deduceStage3 IntBinaryOp
stage3Deducer INT_SRIGHT = deduceStage3 IntBinaryOp
stage3Deducer INT_MULT = deduceStage3 IntBinaryOp
stage3Deducer INT_DIV = deduceStage3 IntBinaryOp
stage3Deducer INT_REM = deduceStage3 IntBinaryOp
stage3Deducer INT_SDIV = deduceStage3 IntBinaryOp
stage3Deducer INT_SREM = deduceStage3 IntBinaryOp
-- Int Unary Op --
stage3Deducer INT_ZEXT = deduceStage3 IntUnaryOp
stage3Deducer INT_SEXT = deduceStage3 IntUnaryOp
stage3Deducer INT_2COMP = deduceStage3 IntUnaryOp
stage3Deducer INT_NEGATE = deduceStage3 IntUnaryOp
-- Float Logic Op --
stage3Deducer FLOAT_EQUAL = deduceStage3 FloatLogicOp
stage3Deducer FLOAT_NOT_EQUAL = deduceStage3 FloatLogicOp
stage3Deducer FLOAT_LESS = deduceStage3 FloatLogicOp
stage3Deducer FLOAT_LESS_EQUAL = deduceStage3 FloatLogicOp
-- Float Bin Op --
stage3Deducer FLOAT_ADD = deduceStage3 FloatBinOp
stage3Deducer FLOAT_SUB = deduceStage3 FloatBinOp
stage3Deducer FLOAT_MULT = deduceStage3 FloatBinOp
stage3Deducer FLOAT_DIV = deduceStage3 FloatBinOp
-- Float Unary Op --
stage3Deducer FLOAT_NEG = deduceStage3 FloatUnaryOp
stage3Deducer FLOAT_ABS = deduceStage3 FloatUnaryOp
stage3Deducer FLOAT_SQRT = deduceStage3 FloatUnaryOp
stage3Deducer FLOAT_CEIL = deduceStage3 FloatUnaryOp
stage3Deducer FLOAT_FLOOR = deduceStage3 FloatUnaryOp
stage3Deducer FLOAT_ROUND = deduceStage3 FloatUnaryOp
stage3Deducer FLOAT_NAN = deduceStage3 FloatUnaryOp
-- Bool Bin Op --
stage3Deducer BOOL_XOR = deduceStage3 BoolBinOp
stage3Deducer BOOL_AND = deduceStage3 BoolBinOp
stage3Deducer BOOL_OR = deduceStage3 BoolBinOp
-- Bool Unary Op --
stage3Deducer BOOL_NEGATE = deduceStage3 BoolUnaryOp
-- Others --
stage3Deducer COPY = deduceStage3 Copy
stage3Deducer LOAD = deduceStage3 Load
stage3Deducer STORE = deduceStage3 Store
-- JUMP --
stage3Deducer BRANCH = deduceStage3 Jump
stage3Deducer BRANCHIND = deduceStage3 Jump
stage3Deducer CALL = deduceStage3 Jump
stage3Deducer CALLIND = deduceStage3 Jump
stage3Deducer RETURN = deduceStage3 Jump
-- Others --
stage3Deducer CBRANCH = deduceStage3 CBranch
stage3Deducer PIECE = deduceStage3 Piece
stage3Deducer SUBPIECE = deduceStage3 SubPiece
stage3Deducer INT2FLOAT = deduceStage3 Int2Float
stage3Deducer FLOAT2FLOAT = deduceStage3 Float2Float
stage3Deducer TRUNC = deduceStage3 Trunc
stage3Deducer PTRADD = deduceStage3 PtrAdd
stage3Deducer PTRSUB = deduceStage3 PtrSub
-- Not Implemented --
stage3Deducer POPCOUNT = deduceStage3 PopCount
stage3Deducer MULTIEQUAL = deduceStage3 MultiEqual
stage3Deducer CAST = deduceStage3 Cast
stage3Deducer INDIRECT = deduceStage3 Indirect
stage3Deducer UNKNOWN = deduceStage3 UnknownOp