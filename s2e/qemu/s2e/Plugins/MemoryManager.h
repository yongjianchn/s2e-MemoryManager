#ifndef S2E_MEMORYMANAGER_H
#define S2E_MEMORYMANAGER_H

#include <s2e/Plugin.h>
#include <s2e/Plugins/CorePlugin.h>
#include <s2e/S2EExecutionState.h>
#include <s2e/Plugins/FunctionMonitor.h>

#include "ModuleExecutionDetector.h"
#include "FunctionMonitor.h"
#include "RawMonitor.h"

#include <string>
#include <vector>
using namespace std;

namespace s2e{

namespace plugins{

class MemoryManager : public Plugin
{
	S2E_PLUGIN
private:
	//m_plugin
	FunctionMonitor *m_functionMonitor;
	RawMonitor *m_RawMonitor;
	ModuleExecutionDetector *m_ModuleExecutionDetector;
	//m_connect
	sigc::connection m_onTranslateInstruction;
	sigc::connection m_onModuleLoad;
	//config
	bool m_terminateOnBugs;
	bool m_detectOnly__kmalloc_ip_options_get;
	bool m_detectOnlyMemcpy_ip_options_get;
	bool m_getParFromStack;
	uint64_t m_pc_ip_options_get_call___kmalloc;
	uint64_t m_pc___kmalloc_return_ip_options_get;
	uint64_t m_pc_rep_movsl_ip_options_get;
	uint64_t m_pc___kmalloc;
public:
	void initialize();
	MemoryManager(S2E* s2e): Plugin(s2e) {};
	//
	typedef std::pair<std::string, std::vector<unsigned char> > VarValuePair;
    typedef std::vector<VarValuePair> ConcreteInputs;
	//
	uint32_t address;
	klee::ref<klee::Expr> size;
	uint32_t edi;
	klee::ref<klee::Expr> ecx;
	struct grantedMemory{
		uint32_t address;
		klee::ref<klee::Expr> size;
	};
	grantedMemory m_grantedMemory;
	vector<grantedMemory> memory_granted_expression;
	
public:
	void onTranslateInstructionStart(ExecutionSignal *signal,
									 S2EExecutionState* state,
									 TranslationBlock *tb,
									 uint64_t pc);
	void onModuleLoad(S2EExecutionState* state,
					   const ModuleDescriptor& mdsc);
public:
	void onFunctionCall_fro(S2EExecutionState *state, uint64_t pc);
	void onFunctionReturn_fro(S2EExecutionState *state, uint64_t pc);
	void onFunctionCall(S2EExecutionState*,FunctionMonitorState*);
	void onFunctionReturn(S2EExecutionState*,bool);
	void onMemcpyExecute(S2EExecutionState *state, uint64_t pc);
	
	klee::ref<klee::Expr> getArgValue(S2EExecutionState* state);
	klee::ref<klee::Expr> getArgValue4(S2EExecutionState* state);
	klee::ref<klee::Expr> getArgValue8(S2EExecutionState* state);
	klee::ref<klee::Expr> getArgValue12(S2EExecutionState* state);
	klee::ref<klee::Expr> getArgValue16(S2EExecutionState* state);
	bool check___kmalloc(uint32_t address, klee::ref<klee::Expr> size, S2EExecutionState *state);
	bool check_rep(uint32_t edi, klee::ref<klee::Expr> ecx, S2EExecutionState *state);
	
	void grant(void);
	void printConstraintExpr(S2EExecutionState* state);
};

}//namespace plugins
}//namespace s2e
#endif
