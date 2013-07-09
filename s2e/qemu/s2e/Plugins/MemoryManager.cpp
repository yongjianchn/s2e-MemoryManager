
#include "MemoryManager.h"
#include "LibraryCallMonitor.h"

#include <s2e/S2E.h>
#include <s2e/ConfigFile.h>
#include <s2e/Utils.h>
#include <s2e/S2EExecutionState.h>
#include <s2e/S2EExecutor.h>
#include <klee/Solver.h>
#include <klee/Constraints.h>
#include "../../../klee/lib/Core/AddressSpace.h"
#include "../../../klee/include/klee/ExecutionState.h"
#include <iostream>
#include <sstream>

extern "C" {
#include "config.h"
#include "qemu-common.h"
#include "sysemu.h"
#include "cpus.h"

#include "tcg-llvm.h"
#include "cpu.h"

	extern struct CPUX86State *env;
}

namespace s2e{

namespace plugins{

S2E_DEFINE_PLUGIN(MemoryManager, "MemoryManager plugin", "",);

void MemoryManager::initialize()
{
	//get config
	ConfigFile *cfg = s2e()->getConfig();
	m_terminateOnBugs = cfg->getBool(getConfigKey() + ".terminateOnBugs", true);
	m_getParFromStack = cfg->getBool(getConfigKey() + ".getParFromStack", true);
	m_pc___kmalloc = cfg->getInt(getConfigKey() + ".pc___kmalloc");
	//plugins
	m_functionMonitor = (s2e::plugins::FunctionMonitor*)(s2e()->getPlugin("FunctionMonitor"));
	m_RawMonitor = (s2e::plugins::RawMonitor*)(s2e()->getPlugin("RawMonitor"));
	
	//signals
	m_onModuleLoad = m_RawMonitor->onModuleLoad.connect(sigc::mem_fun(*this,
					 &MemoryManager::onModuleLoad));
	/*
	备注：RawMonitor本身是存在很大问题的，它发出的ModuleLoad信号是虚假的，只要系统启动，第一条指令就发所有配置的moduleLoad信号
	 可以修改完善RawMonitor，但是它跟插件的核心问题无关，暂且不理
	*/
    m_onTranslateInstruction = s2e()->getCorePlugin()->onTranslateInstructionStart.connect(sigc::mem_fun(*this, 
							   &MemoryManager::onTranslateInstructionStart));
}

void MemoryManager::onTranslateInstructionStart(
	ExecutionSignal *signal,
	S2EExecutionState* state,
	TranslationBlock *tb,
	uint64_t pc)
{
	//检测rep movs指令
	uint32_t inst=0;	
	state->readMemoryConcrete(pc, &inst, 2);
	
	/*---op:f3a*；对应的是rep movs；rep stos；rep lods；repe cmps;repe scas；
	这种判断不包含repne cmps；repne scas等因此感觉它没有道理，
	而且repe cmps等感觉不必判断，判断rep movs就能达到检测目的*/
	
	//inst=inst&0xf0ff;
	//if(inst == 0xa0f3)
	
	//by xyj---op:f3a[4,5]；对应的仅是rep movs
	inst=inst&0xfeff;
	if(inst == 0xa4f3)//2013-06-20修改--xuyongjian-仅匹配rep movs
	{
		signal->connect(sigc::mem_fun(*this, 
									  &MemoryManager::onMemcpyExecute));
	}
}

void MemoryManager::onModuleLoad(S2EExecutionState* state,
								 const ModuleDescriptor& module)
{
	s2e()->getWarningsStream() << "---onModuleLoad" << '\n';
	uint64_t wantedPc = m_pc___kmalloc;
	uint64_t wantedCr3 = 0;
	FunctionMonitor::CallSignal *cs = m_functionMonitor->getCallSignal(state, wantedPc, wantedCr3);
	cs->connect(sigc::mem_fun(*this, &MemoryManager::onFunctionCall));
}

void MemoryManager::onFunctionCall(S2EExecutionState* state, FunctionMonitorState *fns)
{
	//s2e()->getMessagesStream() << "---onFunctionCall" << '\n';
	
	if(m_getParFromStack)
	{
		//get size[2.6.0]
		size = MemoryManager::getArgValue4(state);
	}
	else
	{	
		//get size for newkernel[3.3.1]
		size = state->readCpuRegister(offsetof(CPUX86State, regs[R_EAX]), klee::Expr::Int32);
	}
	
	if (!isa<klee::ConstantExpr>(size))
	{
		s2e()->getWarningsStream() << "=============================================" << '\n';
		s2e()->getWarningsStream() << "KMALLOCSYMBOLIC: kmalloc size is symbolic" << '\n';
		s2e()->getWarningsStream() << "=============================================" << '\n';

		s2e()->getWarningsStream() << "分配的size表达式(如果是数，那么是16进制)：" << size << '\n';
		//打印完整路径约束
		printConstraintExpr(state);
	}
	//s2e()->getMessagesStream() << "分配的size表达式(如果是数，那么是16进制)：" << size << '\n';
	
	//检测分配的size
	check___kmalloc_size(size,state);
	
	//注册return时调用的函数
	bool test = false;
	FUNCMON_REGISTER_RETURN_A(state, fns, MemoryManager::onFunctionReturn, test);
}

void MemoryManager::onFunctionReturn(S2EExecutionState* state,bool test)
{
	//s2e()->getMessagesStream() << "---onFunctionReturn" << '\n';
	//get address
	state->readCpuRegisterConcrete(CPU_OFFSET(regs[R_EAX]),&address , 4);
	//s2e()->getMessagesStream() << "分配的address （eax）:" << hexval(address) << '\n';
	//check?
	//因为s2e本身的机制，在此处得到的分配长度size会是具体化过的，
	//所以不能在此处检测分配的size，应当在调用的时候进行检测
	//而return之后会再符号化
	
	//grant();//如果保存所有的__kmalloc，vector会崩 TODO
}
void MemoryManager::onMemcpyExecute(S2EExecutionState *state, uint64_t pc)
{
	//get edi
	state->readCpuRegisterConcrete(offsetof(CPUX86State, regs[R_EDI]), &edi, sizeof(edi));
	//get ecx
	ecx = state->readCpuRegister(offsetof(CPUX86State, regs[R_ECX]), klee::Expr::Int32);
	
	//check
	check_rep(edi,ecx,state);
}
klee::ref<klee::Expr> MemoryManager::getArgValue(S2EExecutionState* state)
{	
	uint64_t sp = state->getSp();
	klee::ref<klee::Expr> size = state->readMemory(sp, klee::Expr::Int32);
	return size;
}
klee::ref<klee::Expr> MemoryManager::getArgValue4(S2EExecutionState* state)
{	
	uint64_t sp = state->getSp();
	klee::ref<klee::Expr> size = state->readMemory(sp + 4, klee::Expr::Int32);
	return size;
}
klee::ref<klee::Expr> MemoryManager::getArgValue8(S2EExecutionState* state)
{	
	uint64_t sp = state->getSp();
	klee::ref<klee::Expr> size = state->readMemory(sp + 8, klee::Expr::Int32);
	return size;
}klee::ref<klee::Expr> MemoryManager::getArgValue12(S2EExecutionState* state)
{	
	uint64_t sp = state->getSp();
	klee::ref<klee::Expr> size = state->readMemory(sp + 12, klee::Expr::Int32);
	return size;
}klee::ref<klee::Expr> MemoryManager::getArgValue16(S2EExecutionState* state)
{	
	uint64_t sp = state->getSp();
	klee::ref<klee::Expr> size = state->readMemory(sp + 16, klee::Expr::Int32);
	return size;
}

void MemoryManager::grant()
{
	m_grantedMemory.address = address;
	m_grantedMemory.size = size;
	s2e()->getWarningsStream() << "---grant Memory map address: " << hexval(address) << " size: " << size << '\n';
	memory_granted_expression.push_back(m_grantedMemory);
}

bool MemoryManager::check___kmalloc_size(klee::ref<klee::Expr> size, S2EExecutionState *state)
{
	bool isok = true;
	//size具体值
	if (isa<klee::ConstantExpr>(size))
	{
		int value = cast<klee::ConstantExpr>(size)->getZExtValue();
		if (value <= 0 || value >= 0xf0000)
		{
			s2e()->getWarningsStream() << "============================================================" << '\n';
			s2e()->getWarningsStream() << "BUG: __kmalloc [Size <= 0||Size >= 0xf0000] Size: " << value << '\n';
			s2e()->getWarningsStream() << "============================================================" << '\n';
			//打印完整路径约束
			printConstraintExpr(state);
			if(m_terminateOnBugs)
			{
				s2e()->getExecutor()->terminateStateEarly(*state, "Killed by MemoryManager: __kmalloc size is not valid\n");
			}
			isok = false;
			
		}
	}
	//如果size是符号值
	else
	{
		//求解出size=0的时候外界的输入是多少，也就是外界传入什么值的时候可以造成size会为=0
		bool isTrue;
		//klee::ref<klee::Expr> cond = klee::SleExpr::create(size, 
		klee::ref<klee::Expr> cond = klee::EqExpr::create(size, 
									 klee::ConstantExpr::create( 0, size.get()->getWidth()));
		if (!(s2e()->getExecutor()->getSolver()->mayBeTrue(klee::Query(state->constraints, cond), isTrue))) { 
			s2e()->getWarningsStream() << "failed to assert the condition" << '\n';
			return false;
		}
		if (isTrue) {
			ConcreteInputs inputs;
			ConcreteInputs::iterator it; 
			
			//把state的正确约束保存到constraints_before
			klee::ConstraintManager constraints_before(state->constraints);
			klee::ConstraintManager *tmp_constraints;
			tmp_constraints = &state->constraints;
			
			//*****************************************输入值求解***********************************************
			s2e()->getExecutor()->addConstraint(*state, cond);
			s2e()->getExecutor()->getSymbolicSolution(*state, inputs);
			
			s2e()->getWarningsStream() << "======================================================" << '\n';
			s2e()->getWarningsStream() << "BUG:on this condition __kmalloc size will <= 0" << '\n';
			//s2e()->getWarningsStream() << "BUG:on this condition __kmalloc size will = 0" << '\n';
			s2e()->getWarningsStream() << "Condition: " << '\n';
			
			for (it = inputs.begin(); it != inputs.end(); ++it) {
				const VarValuePair &vp = *it;
				s2e()->getWarningsStream() << vp.first << " : ";
				for (unsigned i=0; i<vp.second.size(); ++i) {
					s2e()->getWarningsStream() << hexval((unsigned char) vp.second[i]) << " ";
				}
				s2e()->getWarningsStream() << '\n';
			}
			
			///added by xyj 05.23
			/*
			for (int i = 0; i < int((state->symbolics).size()); i++)
			{
			  
			 if((state->addressSpace).findObject((state->symbolics[i]).first) == NULL)
			 {
			  s2e()->getMessagesStream() << "没有找到memoryObject对应的objectState"<<'\n';
			  continue;
			 }
			  
			 const klee::ObjectState *ob = (state->addressSpace).findObject((state->symbolics[i]).first);
			  
			 uint64_t address_par = state->symbolics[i].first->address;
			 unsigned size_par = state->symbolics[i].first->size;
			  
			 for (int j = 0; j < size_par; j++)
			 {
			  klee::ref<klee::Expr> para = state->readMemory(address_par+j,1);
			  cond = klee::NeExpr::create(para, 
				  klee::ConstantExpr::create(uint64_t(inputs[i].second[j]), para.get()->getWidth()));	
			  if (!(s2e()->getExecutor()->getSolver()->mayBeTrue(klee::Query(state->constraints, cond), isTrue))) 
			  { 
			   s2e()->getMessagesStream() << "failed to assert the condition" << '\n';
			   return false;
			  }
			  //s2e()->getExecutor()->addConstraint(*state, cond);
			 }
			}
			inputs.clear();
			s2e()->getExecutor()->getSymbolicSolution(*state, inputs);
			for (it = inputs.begin(); it != inputs.end(); ++it) {
			 const VarValuePair &vp = *it;
			 s2e()->getMessagesStream() << vp.first << " : ";
			 for (unsigned i=0; i<vp.second.size(); ++i) {
			  s2e()->getMessagesStream() << hexval((unsigned char) vp.second[i]) << " ";
			 }
			 s2e()->getMessagesStream() << '\n';
			}
			*/
			s2e()->getWarningsStream() << "======================================================" << '\n';
			//*********************************************************************************************
			
			//删除修改过的约束；恢复原来的正确约束
			tmp_constraints->empty();
			state->constraints = constraints_before;
			
			//打印完整路径约束
			printConstraintExpr(state);
			
			isok = false;
			if(m_terminateOnBugs)
			{
				s2e()->getExecutor()->terminateStateEarly(*state, "Killed by MemoryManager: __kmalloc size is not valid[size <= 0]\n");
				//s2e()->getExecutor()->terminateStateEarly(*state, "Killed by MemoryManager: __kmalloc size is not valid[size = 0]\n");
			}
		}
		
	}
	return isok;
}
bool MemoryManager::check_rep(uint32_t edi, klee::ref<klee::Expr> ecx, S2EExecutionState *state)
{
	bool isok = true;
	//检查memcpy size访问是否合法
	//concrete
	if(isa<klee::ConstantExpr>(ecx))
	{
		int ecx_con = cast<klee::ConstantExpr>(ecx)->getZExtValue();
		if(ecx_con < 0 || ecx_con > 0xf0000) 
		{
			s2e()->getWarningsStream() << "============================================================" << '\n';
			s2e()->getWarningsStream() << "BUG: memcpy [Size < 0||Size > 0xf0000] Size: " << hexval(ecx_con) << '\n';
			s2e()->getWarningsStream() << "============================================================" << '\n';
			//打印完整路径约束
			printConstraintExpr(state);
			
			isok = false;
			if(m_terminateOnBugs)
			{
				s2e()->getExecutor()->terminateStateEarly(*state, "Killed by MemoryManager: memcpy lenth is not valid\n");
			}
		}
	}
	//symbolic
	else
	{
		bool isTrue;
		klee::ref<klee::Expr> cond = klee::SgeExpr::create(ecx, 
									 klee::ConstantExpr::create( 0xf0000, size.get()->getWidth()));
		if (!(s2e()->getExecutor()->getSolver()->mayBeTrue(klee::Query(state->constraints, cond), isTrue))) { 
			s2e()->getWarningsStream() << "failed to assert the condition" << '\n';
			return false;
		}
		if (isTrue) {
			ConcreteInputs inputs;
			ConcreteInputs::iterator it; 
			
			//把state的正确约束保存到constraints_before
			klee::ConstraintManager constraints_before(state->constraints);
			klee::ConstraintManager *tmp_constraints;
			tmp_constraints = &state->constraints;
			
			//*****************************************输入值求解***********************************************
			s2e()->getExecutor()->addConstraint(*state, cond);
			s2e()->getExecutor()->getSymbolicSolution(*state, inputs);
			
			s2e()->getWarningsStream() << "======================================================" << '\n';
			s2e()->getWarningsStream() << "BUG:on this condition memcpy size will >= 0xf0000" << '\n';
			s2e()->getWarningsStream() << "Condition: " << '\n';
			for (it = inputs.begin(); it != inputs.end(); ++it) {
				const VarValuePair &vp = *it;
				s2e()->getWarningsStream() << vp.first << " : ";
				for (unsigned i=0; i<vp.second.size(); ++i) {
					s2e()->getWarningsStream() << hexval((unsigned char) vp.second[i]) << " ";
				}
				s2e()->getWarningsStream() << '\n';
			}
			s2e()->getWarningsStream() << "======================================================" << '\n';
			//**************************************************************************************************
			
			//删除修改过的约束；恢复原来的正确约束
			tmp_constraints->empty();
			state->constraints = constraints_before;
			
			//打印完整路径约束
			printConstraintExpr(state);
			
			isok = false;
			if(m_terminateOnBugs)
			{
				s2e()->getExecutor()->terminateStateEarly(*state, "Killed by MemoryManager: memcpy size is not valid\n");
			}
		}
	}
	return isok;
}
void MemoryManager::printConstraintExpr(S2EExecutionState* state)
{
	s2e()->getWarningsStream() << "----------路径约束-----------" << '\n' ;
	for (klee::ConstraintManager::const_iterator it = state->constraints.begin(),ie = state->constraints.end(); 
			it != ie; ++it)
	{
		s2e()->getWarningsStream() << *it << '\n' ;
	}
	s2e()->getWarningsStream() << "----------约束结束-----------" << '\n' ;
}
}//namespace plugins

}//namespace s2e
