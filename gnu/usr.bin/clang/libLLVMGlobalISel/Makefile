# $OpenBSD: Makefile,v 1.12 2025/06/11 17:46:32 robert Exp $

LIB=	LLVMGlobalISel
NOPROFILE=

CPPFLAGS+=-I${LLVM_SRC}/include/llvm/CodeGen/GlobalISel

SRCS+=	CSEInfo.cpp \
	GISelKnownBits.cpp \
	CSEMIRBuilder.cpp \
	CallLowering.cpp \
	GlobalISel.cpp \
	Combiner.cpp \
	CombinerHelper.cpp \
	CombinerHelperVectorOps.cpp \
	GIMatchTableExecutor.cpp \
	GISelChangeObserver.cpp \
	IRTranslator.cpp \
	InlineAsmLowering.cpp \
	InstructionSelect.cpp \
	InstructionSelector.cpp \
	LegalityPredicates.cpp \
	LegalizeMutations.cpp \
	Legalizer.cpp \
	LegalizerHelper.cpp \
	LegalizerInfo.cpp \
	LegacyLegalizerInfo.cpp \
	LoadStoreOpt.cpp \
	Localizer.cpp \
	LostDebugLocObserver.cpp \
	MachineIRBuilder.cpp \
	RegBankSelect.cpp \
	GlobalISelUtils.cpp

GlobalISelUtils.cpp:
	ln -s ${LLVM_SRCS}/lib/CodeGen/GlobalISel/Utils.cpp $@

.PATH:	${.CURDIR}/../../../llvm/llvm/lib/CodeGen/GlobalISel

CLEANFILES+= GlobalISelUtils.cpp
