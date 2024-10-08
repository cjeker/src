//===-- ThreadOpenBSDKernel.h ------------------------------------- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#ifndef LLDB_SOURCE_PLUGINS_PROCESS_OPENBSDKERNEL_THREADOPENBSDKERNEL_H
#define LLDB_SOURCE_PLUGINS_PROCESS_OPENBSDKERNEL_THREADOPENBSDKERNEL_H

#include "lldb/Target/Thread.h"

class ThreadOpenBSDKernel : public lldb_private::Thread {
public:
  ThreadOpenBSDKernel(lldb_private::Process &process, lldb::tid_t tid,
		      lldb::addr_t pcb, std::string thread_name);

  ~ThreadOpenBSDKernel() override;

  void RefreshStateAfterStop() override;

  lldb::RegisterContextSP GetRegisterContext() override;

  lldb::RegisterContextSP
  CreateRegisterContextForFrame(lldb_private::StackFrame *frame) override;

  const char *GetName() override {
    if (m_thread_name.empty())
      return nullptr;
    return m_thread_name.c_str();
  }

  void SetName(const char *name) override {
    if (name && name[0])
      m_thread_name.assign(name);
    else
      m_thread_name.clear();
  }

protected:
  bool CalculateStopInfo() override;

private:
  std::string m_thread_name;
  lldb::RegisterContextSP m_thread_reg_ctx_sp;
  lldb::addr_t m_pcb;
};

#endif // LLDB_SOURCE_PLUGINS_PROCESS_OPENBSDKERNEL_THREADOPENBSDKERNEL_H
