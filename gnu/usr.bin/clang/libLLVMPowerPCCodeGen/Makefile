# $OpenBSD: Makefile,v 1.12 2025/06/11 17:46:32 robert Exp $

LIB=	LLVMPowerPCCodeGen
NOPROFILE=

CPPFLAGS+=	-I${.OBJDIR}/../include/llvm/PowerPC \
		-I${LLVM_SRCS}/lib/Target/PowerPC

# GISel
SRCS+=	PPCInstructionSelector.cpp \
	PPCCallLowering.cpp \
	PPCRegisterBankInfo.cpp \
	PPCLegalizerInfo.cpp

SRCS+=	PPCBoolRetToInt.cpp \
	PPCAsmPrinter.cpp \
	PPCBranchSelector.cpp \
	PPCBranchCoalescing.cpp \
	PPCCallingConv.cpp \
	PPCCCState.cpp \
	PPCCTRLoops.cpp \
	PPCCTRLoopsVerify.cpp \
	PPCExpandAtomicPseudoInsts.cpp \
	PPCHazardRecognizers.cpp \
	PPCInstrInfo.cpp \
	PPCISelDAGToDAG.cpp \
	PPCISelLowering.cpp \
	PPCEarlyReturn.cpp \
	PPCFastISel.cpp \
	PPCFrameLowering.cpp \
	PPCLoopInstrFormPrep.cpp \
	PPCMCInstLower.cpp \
	PPCMachineFunctionInfo.cpp \
	PPCMachineScheduler.cpp \
	PPCMacroFusion.cpp \
	PPCMergeStringPool.cpp \
	PPCMIPeephole.cpp \
	PPCRegisterInfo.cpp \
	PPCReturnProtectorLowering.cpp \
	PPCSubtarget.cpp \
	PPCTargetMachine.cpp \
	PPCTargetObjectFile.cpp \
	PPCTargetTransformInfo.cpp \
	PPCTOCRegDeps.cpp \
	PPCTLSDynamicCall.cpp \
	PPCVSXCopy.cpp \
	PPCReduceCRLogicals.cpp \
	PPCVSXFMAMutate.cpp \
	PPCVSXSwapRemoval.cpp \
	PPCExpandISEL.cpp \
	PPCPreEmitPeephole.cpp \
	PPCLowerMASSVEntries.cpp \
	PPCGenScalarMASSEntries.cpp

.PATH:	${.CURDIR}/../../../llvm/llvm/lib/Target/PowerPC
.PATH:	${.CURDIR}/../../../llvm/llvm/lib/Target/PowerPC/GISel
