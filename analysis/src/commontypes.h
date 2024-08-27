/*
 * common types
 * 2018 Tong Zhang<t.zhang2@partner.samsung.com>
 */
#ifndef _COMMON_TYPES_
#define _COMMON_TYPES_

#include <list>
#include <stack>
#include <queue>
#include <map>
#include <set>
#include <unordered_map>
#include <unordered_set>

#include <llvm/IR/Function.h>
#include <llvm/IR/Constants.h>
using namespace llvm;

enum _REACHABLE
{
    RCHKED,//fully checked
    RPRCHK,//partically checked
    RNOCHK,//no check at all
    RKINIT,//hit kernel init functions, ignored
    RUNRESOLVEABLE,//unable to resolve due to indirect call
    RNA,//not available
};

typedef std::list<std::string> StringList;
typedef std::list<Value*> ValueList;
typedef std::list<Use*> UseList;
typedef std::list<Instruction*> InstructionList;
typedef std::list<CallInst*> CallInstList;
typedef std::list<BasicBlock*> BasicBlockList;
typedef std::list<Function*> FunctionList;
typedef std::list<Type*> TypeList;
typedef std::list<int> Indices;

typedef std::unordered_set<int> CodeSet;
typedef std::unordered_set<std::string> StringSet;
typedef std::unordered_set<Value*> ValueSet;
typedef std::unordered_set<Use*> UseSet;
typedef std::unordered_set<Type*> TypeSet;
typedef std::unordered_set<Instruction*> InstructionSet;
typedef std::unordered_set<CallInst*> CallInstSet;
typedef std::unordered_set<const Instruction*> ConstInstructionSet;
typedef std::unordered_set<BasicBlock*> BasicBlockSet;
typedef std::unordered_set<Function*> FunctionSet;
typedef std::unordered_set<CallInst*> InDirectCallSites;
typedef ValueSet ModuleSet;
typedef std::unordered_set<Argument*> ArgumentSet;

//dynamic KMI
//pair between indices and function set(fptr stored into this position)
typedef std::pair<Indices*,FunctionSet*> IFPair;
//all those pairs
typedef std::list<IFPair*> IFPairs;
//map struct type to pairs
typedef std::unordered_map<StructType*, IFPairs*> DMInterface;
typedef std::pair<StructType*, Indices*> Field;

typedef std::unordered_map<Function*,_REACHABLE> FunctionToCheckResult;
typedef std::unordered_map<Function*, InstructionSet*> Function2ChkInst;
typedef std::unordered_map<Function*, InstructionSet*> Function2CSInst;
typedef std::unordered_map<Function*, int> FunctionData;
typedef std::unordered_map<Type*, std::unordered_set<Function*>*> TypeToFunctions;
typedef std::unordered_map<Type*, std::unordered_set<int>> Type2Fields;
typedef std::unordered_map<Type*, InstructionSet*> Type2ChkInst;
typedef std::unordered_map<Type*, ModuleSet*> ModuleInterface2Modules;
typedef std::unordered_map<Value*, InstructionSet*> Value2ChkInst;
typedef std::unordered_map<Instruction*, FunctionSet*> Inst2Func;
typedef std::unordered_map<const Instruction*, FunctionSet*> ConstInst2Func;
typedef std::unordered_map<std::string, int> Str2Int;

typedef std::map<std::string, StructType*> StructTypeMap;
typedef std::map<StructType*, int> StructIdxMap;
typedef std::set<StructType*> StructTypeSet;
typedef std::list<StructType*> StructTypeList;

typedef std::map<StructType*, StructTypeMap*> STy2PTy;
typedef std::set<Indices*> IdxSet;
typedef std::map<StructType*, IdxSet*> Sty2Idxes;

typedef std::map<int, Function*> IntFunctionMap;
typedef std::map<Instruction*, TypeSet*> Inst2Type;
typedef std::map<Function*, int> FunctionIntMap;

typedef std::map<Value*, ValueSet*> Value2Val;
typedef std::unordered_set<StringList *> StringListSet;
typedef std::map<Type *, StringListSet*> Ty2StrListSet;
typedef std::unordered_map<Use*, TypeSet*> Use2Type;
typedef std::unordered_map<Type*, ValueSet*> Type2ChkVal;
typedef std::unordered_map<Function*,Type2ChkVal> Function2TypeVal;
typedef std::unordered_map<Type*,FunctionSet*> Type2Function;
typedef std::unordered_map<Argument*, TypeSet*> Arg2Type;
typedef std::unordered_map<Function*, TypeSet*> Function2Type;
typedef std::unordered_map<Value*, TypeSet*> Val2Type;
typedef std::map<std::pair<StructType*, Indices*>, TypeSet*> Field2Type;
typedef std::map<std::pair<StructType*, Indices*>, CodeSet*> Field2Code;
typedef std::unordered_set<Field*> FieldSet;
typedef std::unordered_map<StructType*, std::map<Indices*, InstructionSet*>*> Sty2Inst;

typedef std::unordered_set<ValueList*> VLSet;
typedef std::map<Instruction*, VLSet*> Inst2Uselists;
typedef std::map<Type*, VLSet*> Ty2Uselists;
typedef std::pair<User*, int> UserInt;
typedef std::unordered_set<UserInt*> UserIntSet;
typedef std::unordered_map<Function*, UserIntSet*> F2UISet;
typedef std::set<std::pair<Value*, Value*>> VPSet;
typedef std::unordered_map<Function*, VPSet*> Func2ValPair;
typedef std::unordered_map<Type*, Func2ValPair*> Type2FVP;
typedef std::unordered_map<Type*, UserIntSet*> Ty2UISet;

typedef std::unordered_map<int, Indices*> intIdxMap;
typedef std::unordered_map<int, Type*> intTyMap;
typedef std::unordered_map<StructType*, intIdxMap*> Sty2Idx;
typedef std::unordered_map<StructType*, intTyMap*> Sty2Ety;
typedef std::unordered_map<Instruction*, Function*> InstFuncMap;
typedef std::unordered_map<Function*, Indices*> Func2Ind;

typedef std::unordered_map<ConstantExpr*, Function2ChkInst*> CE2FISet;
typedef std::unordered_map<ConstantExpr*, InstructionSet*> CE2Inst;
typedef std::unordered_map<ValueList*, Indices> VLIdxSet;
typedef std::unordered_map<Value*, Indices*> Val2Idx;
typedef std::unordered_map<Type*, TypeSet*> Ty2TySet;


class create {
public:
    Function *func;
    Value *src;
    Value *dest;
    int code;
};
   
class check {
public:
    Function *func;
    Value *base;
    int opNum;
    int code;
    ValueList *ul;

    bool is_same(Function *_func, Value *_base, int _opNum,
                     int _code, ValueList *_ul) {
        if (func != _func)
            return false;
        if (base != _base)
            return false;
        if (opNum != _opNum) {
            return false;
        }
        if (code != _code) {
            return false;
        }

        if (ul->size() != _ul->size())
            return false;

        auto iter1 = ul->begin();
        auto iter2 = _ul->begin();
        for(; iter1 != ul->end() && iter2 != _ul->end();
            ++iter1, ++iter2) {
        if (*iter1 != *iter2)
            return false;
        }
        return true;
    }
};

class copy {
public:
    Function *func;
    Value *base;
    int opNum;
};

class convert {
public:
    Function *func;
    Instruction *base;
    int opNum;
    int code;
    VLSet *ulset;
};

class strip {
public:
    Function *func;
    User *base;
    int opNum;
};

class mte {
public:
    Function *func;
    Instruction *base;
    int opNum;
    int code;
    VLSet *ulset;
};

typedef std::unordered_set<check*> checkDump;
typedef std::unordered_set<create*> createDump;
typedef std::unordered_set<convert*> convertDump;
typedef std::unordered_set<strip*> stripDump;
typedef std::unordered_set<mte*> mteDump;
#endif//_COMMON_TYPES_
