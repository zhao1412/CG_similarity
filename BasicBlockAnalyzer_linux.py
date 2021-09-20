# -*- coding:utf8 -*-
import idc
import idautils
import os
import sys
import idaapi
import json
import datetime
import traceback
import time
import codecs

###########################################################################################

global g_xrefInformationList_list
global g_raw_xref_InformationList_list
global g_raw_xref_map
global error_logfile

CMPS  = [
	idaapi.NN_cmp,
	idaapi.NN_test,
	idaapi.NN_xor,
	idaapi.NN_sub,
	idaapi.NN_add
]

CALLS = [
		idaapi.NN_call,
		idaapi.NN_callfi,
		idaapi.NN_callni]

RETS = [
		idaapi.NN_retf,
		idaapi.NN_retfd,
		idaapi.NN_retfq,
		idaapi.NN_retfw,
		idaapi.NN_retn,
		idaapi.NN_retnd,
		idaapi.NN_retnq,
		idaapi.NN_retnw]

UCOND_BRANCHES = [
		idaapi.NN_jmp,
		idaapi.NN_jmpfi,
		idaapi.NN_jmpni,
		idaapi.NN_jmpshort]

COND_BRANCHES = [
		idaapi.NN_ja,
		idaapi.NN_jae,
		idaapi.NN_jb,
		idaapi.NN_jbe,
		idaapi.NN_jc,
		idaapi.NN_jcxz,
		idaapi.NN_je,
		idaapi.NN_jecxz,
		idaapi.NN_jg,
		idaapi.NN_jge,
		idaapi.NN_jl,
		idaapi.NN_jle,
		idaapi.NN_jna,
		idaapi.NN_jnae,
		idaapi.NN_jnb,
		idaapi.NN_jnbe,
		idaapi.NN_jnc,
		idaapi.NN_jne,
		idaapi.NN_jng,
		idaapi.NN_jnge,
		idaapi.NN_jnl,
		idaapi.NN_jnle,
		idaapi.NN_jno,
		idaapi.NN_jnp,
		idaapi.NN_jns,
		idaapi.NN_jnz,
		idaapi.NN_jo,
		idaapi.NN_jp,
		idaapi.NN_jpe,
		idaapi.NN_jpo,
		idaapi.NN_jrcxz,
		idaapi.NN_js,
		idaapi.NN_jz]

EXIT_FUNCTIONS = [
		"xexit",
		"exit",
		".__stack_chk_fail",
		"__exit",
		"_bfd_error_handler"]

EXIT_INSTRUCTIONS = [
		idaapi.NN_hlt
]

def get_section_information(input_output_file_path,input_output_file_name):
	global g_sectionList_list
	file_path = input_output_file_path + input_output_file_name + "_Section.json"
	file_content_dict = {}

        fd = codecs.open(file_path,'wb',encoding='utf-8')

	for current_seg in Segments():
		currentSection_dict = {}
		currentSection_dict["Name"]         = SegName(current_seg)
		currentSection_dict["StartAddress"] = hex(SegStart(current_seg)).replace("L","")
		currentSection_dict["EndAddress"]   = hex(SegEnd(current_seg)).replace("L","")
		g_sectionList_list.append(currentSection_dict)
		#print('%s %x-%x' % ( SegName(current_seg), SegStart(current_seg), SegEnd(current_seg)) )

	g_sectionList_list.sort(key=lambda k: (k.get('StartAddress', 0)))
	file_content_dict["Section"] = g_sectionList_list

	fd.write(json.dumps(file_content_dict,sort_keys=True, indent=4, separators=(',', ':')))
	fd.close()
	print("get_section_information ok")


'''
	FunctionName:
		get_function_information
	Argument:
	
	Result:

	Comment:
		input_output_file_path,input_output_file_name
		
'''
def get_function_information(input_output_file_path,input_output_file_name):
	file_path = input_output_file_path + input_output_file_name + "_Function.json"
	file_content_dict = {}
	function_list = []

        fd = codecs.open(file_path,'wb',encoding='utf-8')
	
	for current_function_address in idautils.Functions():
		#print(current_function_address)

		current_function_information_dict = {}
		current_function = idaapi.get_func(current_function_address)
		current_function_information_dict["FunctionName"] =  idc.GetFunctionName(current_function_address)
		#print(idc.GetFunctionName(current_function_address))
		current_function_information_dict["StartAddress"] = hex(current_function.startEA).replace("L","")
		current_function_information_dict["EndAddress"] = hex(current_function.endEA).replace("L","")
		function_list.append(current_function_information_dict)

	function_list.sort(key=lambda k: (k.get('StartAddress', 0)))
	file_content_dict["FunctionList"] = function_list
	file_content_dict["FunctionCount"] = len(function_list)
	fd.write(json.dumps(file_content_dict,sort_keys=True, indent=4, separators=(',', ':')))
	fd.close()
	print("Dump function information ok")

def insert_unique_xref_info(raw_xref_dict,xref_info):
    global g_raw_xref_map
    key = xref_info["CallerInstruction"]
    if key not in raw_xref_dict:
        raw_xref_dict[key] = xref_info

	if xref_info["CallerFunction"] in g_raw_xref_map:
		g_raw_xref_map[xref_info["CallerFunction"]].add(xref_info["CalleeFunction"])
	else:
		g_raw_xref_map[xref_info["CallerFunction"]] = set([xref_info["CalleeFunction"]])

global flow_chart_cache
flow_chart_cache = {}

def get_flow_chart_with_cache(function):
	global flow_chart_cache
	if function in flow_chart_cache:
		return flow_chart_cache[function]
	else:
		flow_chart = idaapi.FlowChart(function,flags=idaapi.FC_PREDS)
		flow_chart_cache[function] = flow_chart
		return flow_chart

'''


'''
def get_raw_xref_information(input_output_file_path,input_output_file_name):
	global g_raw_xref_InformationList_list
        global g_raw_xref_map
	g_raw_xref_InformationList_list = []
        raw_xref_dict = {}

	print("-----------------------------------------get_xref_information-------------------------------------------------")
	file_path = input_output_file_path + input_output_file_name + "_RawXrefInfo.json"
        fd = codecs.open(file_path,'wb',encoding='utf-8')
	xref_information_dcit = {}

	#print(g_xrefInformationList_list)
	for current_function_address in idautils.Functions():
		#print("Current Function:" + hex(current_function_address))
		for caller_address in idautils.CodeRefsTo(current_function_address, 0):
			#get function
			caller_function = idaapi.get_func(caller_address)
			if not caller_function:
				#print("none")
				continue
			current_xref_dict = {}
			current_xref_dict["CalleeFunction"] = hex(current_function_address).replace("0x","ADDR_").replace("L","")
			current_xref_dict["CalleeBasicBlock"] = hex(current_function_address).replace("0x","BB_").replace("L","")
			current_xref_dict["CallerFunction"] = "ADDR_" + hex(caller_function.startEA).replace("0x","").replace("L","")
			flowchart = get_flow_chart_with_cache(caller_function)
                        current_bb_start = 0
			for current_basic_block in flowchart:
				# because endEA means next instruction address. So, it must be > , not >=
				if current_basic_block.startEA <= caller_address and current_basic_block.endEA > caller_address:
					current_bb_start = current_basic_block.startEA
					break

			current_xref_dict["CallerBasicBlock"] = "BB_" + hex(current_bb_start).replace("0x","").replace("L","")
			current_xref_dict["CallerInstruction"] = hex(caller_address).replace("L","")
			#print("xref from: " + current_xref_dict["CallerFunction"] + " to " + current_xref_dict["CalleeFunction"] + " at BB:" + current_xref_dict["CallerBasicBlock"] + " Instruction:" + current_xref_dict["CallerInstruction"])
                        insert_unique_xref_info(raw_xref_dict,current_xref_dict)
	
        g_raw_xref_InformationList_list = raw_xref_dict.values()
	g_raw_xref_InformationList_list.sort(key=lambda k: (k.get('CalleeBasicBlock', 0), k.get('CallerBasicBlock', 0), k.get('CallerFunction',0) ))
	xref_information_dcit["XREF"] = g_raw_xref_InformationList_list
	xref_information_dcit["XREFCount"] = len(g_raw_xref_InformationList_list)
	#json.dump(xref_information_dcit,fd)
	fd.write(json.dumps(xref_information_dcit,sort_keys=True, indent=4, separators=(',', ':')))
	fd.close()
	print("Dump raw xref information ok")


'''
	FunctionName:
		get_xref_information

	Argument:
	

	Result:


	Comment:
		This function is OK
'''
def get_xref_information(input_output_file_path,input_output_file_name):
	global g_xrefInformationList_list
	#print("-----------------------------------------get_xref_information-------------------------------------------------")
	file_path = input_output_file_path + input_output_file_name + "_XrefInfo.json"
        fd = codecs.open(file_path,'wb',encoding='utf-8')
	xref_information_dcit = {}

	#print(g_xrefInformationList_list)
	for current_function_address in idautils.Functions():
		#print("Current Function:" + hex(current_function_address))
		for caller_address in idautils.CodeRefsTo(current_function_address, 0):
			#get function
			if not idaapi.get_func(caller_address):
				#print("none")
				continue
			current_xref_dict = {}
			current_xref_dict["CalleeFunction"] = hex(current_function_address).replace("0x","ADDR_").replace("L","")
			current_xref_dict["CalleeBasicBlock"] = hex(current_function_address).replace("0x","BB_").replace("L","")
			current_xref_dict["CallerFunction"] = "ADDR_" + hex(idaapi.get_func(caller_address).startEA).replace("0x","").replace("L","")
			caller_function = idaapi.get_func(caller_address)
			flowchart = get_flow_chart_with_cache(caller_function)
			for current_basic_block in flowchart:
				# because endEA means next instruction address. So, it must be > , not >=
				if current_basic_block.startEA <= caller_address and current_basic_block.endEA > caller_address:
					current_addr = current_basic_block.startEA
					current_bb_start = current_basic_block.startEA
					#print("current BB:" + hex(current_basic_block.startEA))
					while current_addr < current_basic_block.endEA and current_addr < caller_address:
						#print("current INS:"+ hex(current_addr))
						current_inst = idautils.DecodeInstruction(current_addr)
						if not current_inst is None:
							if current_inst.itype in CALLS:
							#if current_inst.itype in CALLS or current_inst.itype in RETS or current_inst.itype in UCOND_BRANCHES or current_inst.itype in COND_BRANCHES:
								current_bb_start = idc.NextHead(current_addr)
						current_addr = current_addr + current_inst.size
					break

			current_xref_dict["CallerBasicBlock"] = "BB_" + hex(current_bb_start).replace("0x","").replace("L","")
			current_xref_dict["CallerInstruction"] = hex(caller_address).replace("L","")
			#print("xref from: " + current_xref_dict["CallerFunction"] + " to " + current_xref_dict["CalleeFunction"] + " at BB:" + current_xref_dict["CallerBasicBlock"] + " Instruction:" + current_xref_dict["CallerInstruction"])
			if not current_xref_dict in g_xrefInformationList_list:
				g_xrefInformationList_list.append(current_xref_dict)
	
	g_xrefInformationList_list.sort(key=lambda k: (k.get('CalleeBasicBlock', 0), k.get('CallerBasicBlock', 0), k.get('CallerFunction',0) ))
	xref_information_dcit["XREF"] = g_xrefInformationList_list
	#json.dump(xref_information_dcit,fd)
	fd.write(json.dumps(xref_information_dcit,sort_keys=True, indent=4, separators=(',', ':')))
	fd.close()
	print("Dump xref information ok")


def get_raw_call_graph(inputResultFilePath,inputResultFileName):
        print ("get raw call graph ..............................")
	global g_raw_xref_InformationList_list
	global g_raw_xref_map
	file_path =  inputResultFilePath + "CG_" + inputResultFileName + "_raw.dot"
        fd = codecs.open(file_path,'wb',encoding='utf-8')
	fd.write("DiGraph CallGraph"  + "{\n" )
	edge_set = set()

	for (caller_function, callee_functions) in g_raw_xref_map.items():
		for callee_function in callee_functions:
			edge_string = caller_function + "->" + callee_function + "\n"
			fd.write(edge_string)
	fd.write("}\n" )
	fd.close()

	# for aFunc in idautils.Functions():
	# 	func=idaapi.get_func(aFunc)
	# 	#print ("function name:%s" %  idc.GetFunctionName(aFunc))
	# 	fflags = idc.GetFunctionFlags(aFunc)
	# 	if(fflags & FUNC_LIB) or (fflags & FUNC_THUNK):     #not function code
	# 		continue

	# 	if func.startEA in g_raw_xref_map:
	# 		xref_list = g_raw_xref_map[func.startEA]
	# 		for current_xref in xref_list:
	# 			edge_string = current_xref["CallerFunction"] + "->" + current_xref["CalleeFunction"] + "\n"
	# 			if not edge_string in edge_set:
	# 				edge_set.insert(edge_string)
	# 				fd.write( edge_string )
	# fd.write("}\n" )
	# fd.close()
	print("Process Raw Call Graph OK")

'''
	FunctionName:
		get_call_graph
	
	Argument:
	

	Result:


	Comment:
		This function's output has two types, complex and simple.
		Most of the time, we use simple type output.
		Because there are some function names begin with "."
		so, we have to replace them first
'''
def get_call_graph(inputResultFilePath,inputResultFileName):
	global g_xrefInformationList_list
	file_path =  inputResultFilePath + "CG_" + inputResultFileName + ".dot"
        fd = codecs.open(file_path,'wb',encoding='utf-8')
	fd.write("DiGraph CallGraph"  + "{\n" )
	edge_list = []

	for aFunc in idautils.Functions():
		func=idaapi.get_func(aFunc)
		#print ("function name:%s" %  idc.GetFunctionName(aFunc))
		fflags = idc.GetFunctionFlags(aFunc)
		if(fflags & FUNC_LIB) or (fflags & FUNC_THUNK):     #not function code
			continue
		for current_xref in g_xrefInformationList_list:
			current_callee_function = int(current_xref["CalleeFunction"].replace("ADDR_","0x"),16)
			if current_callee_function == func.startEA:
				edge_string = current_xref["CallerFunction"] + "->" + current_xref["CalleeFunction"] + "\n"
				#print(edge_string)
				if not edge_string in edge_list:
					edge_list.append(edge_string)
					fd.write( edge_string )
		'''
		for addr in idautils.CodeRefsTo(func.startEA, 0):
			#print ("xref from:" , hex(addr), "+", hex(func.startEA))
			#print("start EA:" + str(idaapi.get_func(addr)))
			if not idaapi.get_func(addr):
				print("Can't find caller, address :"+ hex(addr) + " Calee Address:" + idc.GetFunctionName(func.startEA))
			else:
				#edge_string = "ADDR_" + hex(idaapi.get_func(addr).startEA).replace("0x","").replace("L","") + "_" + idc.GetFunctionName(addr) + "->" + "ADDR_" + hex(idaapi.get_func(aFunc).startEA).replace("0x","").replace("L","") + "_" + idc.GetFunctionName(aFunc) + "\n"
				edge_string = "ADDR_" + hex(idaapi.get_func(addr).startEA).replace("0x","").replace("L","") + "->" + "ADDR_" + hex(idaapi.get_func(aFunc).startEA).replace("0x","").replace("L","") + "\n"
			#edge_string = "ADDR_" + hex(idaapi.get_func(addr).startEA).replace("0x","").replace("L","") + "->" + "ADDR_" + hex(idaapi.get_func(aFunc).startEA).replace("0x","").replace("L","") + "\n"
			edge_string = edge_string.replace(".","_")
			
			if not edge_string in edge_list:
				edge_list.append(edge_string)
				fd.write( edge_string )
		'''    
	fd.write("}\n" )
	fd.close()
	print("Process Call Graph OK")


'''
	FunctionName:
		add_ret_xref

	Argument:
		inputTargetAddress
		inputNextInstAddress

	Result:

	Comment:
'''
def add_ret_xref( inputTargetAddress, inputNextInstAddress):
	global g_xrefInformationList_list
	#print("add_ret_xref")
	target_function = idaapi.get_func(inputTargetAddress)
	flowchart=idaapi.FlowChart(target_function,flags=idaapi.FC_PREDS)
	count=0
	has_ret = False
	for current_basic_block in flowchart:
		count = count + 1
		current_addr = current_basic_block.startEA
		current_bb_start = current_basic_block.startEA
		#print("current BB:" + hex(current_basic_block.startEA))
		while current_addr < current_basic_block.endEA:
			#print("current INS:"+ hex(current_addr))
			current_inst = idautils.DecodeInstruction(current_addr)
			if not current_inst is None:
				if current_inst.itype in CALLS:
					current_bb_start = idc.NextHead(current_addr)
				if current_inst.itype in RETS:
					#print("ret at:" + hex(current_addr))
					ret_xref_dict = {}
					ret_xref_dict["CalleeFunction"] = hex(idaapi.get_func(inputNextInstAddress).startEA).replace("0x","ADDR_").replace("L","")
					ret_xref_dict["CalleeBasicBlock"] = hex(inputNextInstAddress).replace("0x","BB_").replace("L","")
					ret_xref_dict["CallerFunction"] = hex(target_function.startEA).replace("0x","ADDR_").replace("L","")
					ret_xref_dict["CallerBasicBlock"] = hex(current_bb_start).replace("0x","BB_").replace("L","")
					ret_xref_dict["CallerInstruction"] = hex(current_addr).replace("L","")
					#print(ret_xref_dict)
					if not ret_xref_dict in g_xrefInformationList_list:
						g_xrefInformationList_list.append(ret_xref_dict)
					has_ret = True
				
				current_addr = current_addr + current_inst.size
	
	if has_ret == False:
		#print("no ret")
		for current_basic_block in flowchart:
			current_addr = current_basic_block.startEA
			current_bb_start = current_basic_block.startEA
			while current_addr < current_basic_block.endEA:
				#print("current INS:"+ hex(current_addr))
				current_inst = idautils.DecodeInstruction(current_addr)
				if not current_inst is None:
					if current_inst.itype in CALLS:
						current_bb_start = idc.NextHead(current_addr)
					if current_inst.itype in UCOND_BRANCHES:
						#print("jump at:" + hex(current_addr) + " Target:" + hex(current_inst.Operands[0].addr))
						for current_section in g_sectionList_list:
							if current_section["Name"] == ".plt" or current_section["Name"] == ".plt.got" :
								#print("get plot")
								#print(current_section["Name"]+ " Start:"+ current_section["StartAddress"] + " End:" + current_section["EndAddress"])
								if current_inst.Operands[0].addr >= int(current_section["StartAddress"],16) and current_inst.Operands[0].addr < int(current_section["EndAddress"],16):
									#print("will add return xref")
									jump_xref_dict = {}
									jump_xref_dict["CalleeFunction"] = hex(idaapi.get_func(inputNextInstAddress).startEA).replace("0x","ADDR_").replace("L","")
									jump_xref_dict["CalleeBasicBlock"] = hex(inputNextInstAddress).replace("0x","BB_").replace("L","")
									jump_xref_dict["CallerFunction"] = hex(target_function.startEA).replace("0x","ADDR_").replace("L","")
									jump_xref_dict["CallerBasicBlock"] = hex(current_bb_start).replace("0x","BB_").replace("L","")
									jump_xref_dict["CallerInstruction"] = hex(current_addr).replace("L","")
									#print(jump_xref_dict)
									if not jump_xref_dict in g_xrefInformationList_list:
										g_xrefInformationList_list.append(jump_xref_dict)
					current_addr = current_addr + current_inst.size
	#print("bb count:" + hex(count) )

'''
	FunctionName:
		get_control_flow_graph
	
	Argument:
	

	Result:


	Comment:
		This function construct control flow graph for each function.
		When analyze linux elf, there are many import functions, we have to filter all these functions

'''
def get_control_flow_graph(inputResultFilePath):
	#build cfg file for each function
	print("------------------------------------Get Control Flow Graph---------------------------------------------")
	for aFunc in idautils.Functions():
		new_edge_dict = {}
		func=idaapi.get_func(aFunc)
		#print("=========================Current Function:" + hex(func.startEA)) + "===================================="
		flowchart=get_flow_chart_with_cache(func)
		
		for bb in flowchart:
			current_addr = bb.startEA
			current_bb_start = bb.startEA
			#print("current_bb_start:" + hex(current_bb_start))
			#print("current_bb_end:" + hex(bb.endEA))
			while current_addr < bb.endEA:
				current_inst = idautils.DecodeInstruction(current_addr)
				#print("current instruction :" + hex(current_addr))
				if not current_inst is None:
					'''
						If we meet a call. We have to check the target of the call and add xref
					'''
					#print(hex(current_inst.itype))
					if current_inst.itype in CALLS:
						#cut basic block
						#print("find call at:" + hex(current_addr).replace("L","")+ " Target Address:" + hex(current_inst.Operands[0].addr))
						import_function = False
						# emunerate all sections, whether call target is an import function 
						for current_section in g_sectionList_list:
							if current_section["Name"] == ".plt" or current_section["Name"] == ".plt.got":
								if current_section["StartAddress"] <= current_inst.Operands[0].addr and current_section["EndAddress"] >= current_inst.Operands[0].addr:
									import_function = True
									break
						
						# if it is not an import function or a call register. It is a user-defined function. Add xref.
						#if not import_function and 0 != current_inst.Operands[0].addr:
							#check computable target
					        #        if o_near == idc.GetOpType(current_addr,0) or o_far == idc.GetOpType(current_addr,0) or o_imm == idc.GetOpType(current_addr,0):
					#			add_ret_xref( current_inst.Operands[0].addr, idc.NextHead(current_addr) )

						# if this call is the end of block
						if not idc.NextHead(current_addr) >= func.endEA:
							# add by firefoxxp start. 2020/08/13
							# if the call target is a non-return function, there is no edge to successor
							call_target_function = idc.GetFunctionName(current_inst.Operands[0].addr)
							#print(call_target_function)
							if not call_target_function in EXIT_FUNCTIONS:
								#print("call normal function:" + call_target_function + "at:0x" + str(hex(current_addr)))
								# add edge from call instruction to successor instruction
								edge_string = "BB_" + hex(current_bb_start) + "->" + "BB_" + hex(idc.NextHead(current_addr)) + "\n"
								edge_string = edge_string.replace("0x","")
								edge_string = edge_string.replace("L","")
								#print(edge_string)
								if not edge_string in new_edge_dict:
									new_edge_dict[edge_string]=1

						# bb start point to next instruction
						current_bb_start = idc.NextHead(current_addr)
				current_addr = current_addr + current_inst.size

			for succ_block in bb.succs():
				# basic block end reaches succ block
				if current_bb_start != succ_block.startEA:
					edge_string = "BB_" + hex(current_bb_start) + "->" + "BB_" + hex(succ_block.startEA) + "\n"
					edge_string = edge_string.replace("0x","")
					edge_string = edge_string.replace("L","")
					if not edge_string in new_edge_dict:
						new_edge_dict[edge_string]=1
				# it is a loop
				if current_bb_start == bb.startEA and current_bb_start == succ_block.startEA:
					edge_string = "BB_" + hex(current_bb_start) + "->" + "BB_" + hex(succ_block.startEA) + "\n"
					edge_string = edge_string.replace("0x","")
					edge_string = edge_string.replace("L","")
					if not edge_string in new_edge_dict:
						new_edge_dict[edge_string]=1

		new_edge_list = new_edge_dict.keys()
		new_edge_list.sort()
		if len(new_edge_list) > 0 :
			file_path = inputResultFilePath + "CFG_ADDR_" + hex(aFunc).replace("0x","").replace("L","") + ".dot"
                        fd = codecs.open(file_path,'wb',encoding='utf-8')
			fd.write("DiGraph " + idc.GetFunctionName(aFunc) + "{\n" )
			for current_line in new_edge_list:
				fd.write(current_line)
			fd.write("}\n" )
			fd.close()

		if len(new_edge_list) == 0 :
			file_path = inputResultFilePath + "CFG_ADDR_" + hex(aFunc).replace("0x","").replace("L","") + ".dot"
                        fd = codecs.open(file_path,'wb',encoding='utf-8')
			fd.write("DiGraph " + idc.GetFunctionName(aFunc) + "{\n" )
			for bb in flowchart:
				fd.write( " BB_" + hex(bb.startEA).replace("0x","").replace("L","") )
			fd.write("}\n" )
			fd.close()
			continue


def insert_unique_basic_block_info(BasicBlockMap,BasicBlockInfo):
    key = BasicBlockInfo["BasicBlockStartAddress"] + '_' + BasicBlockInfo["BasicBlockEndAddress"]
    if not key in BasicBlockMap:
        BasicBlockMap[key]=BasicBlockInfo

'''
	FunctionName:
		get_raw_basic_block_information

	Argument:
		input_result_file_path
		input_result_file_name
	Result:

	Comment:
		
'''
def get_raw_basic_block_information( input_result_file_path , input_result_file_name ):
	print("GetRawBasicBlocks")
	FileContent_dict={}
	BasicBlockList_list = []
        BasicBlockMap = {}
	Branch_list= []

	file_path = input_result_file_path + input_result_file_name + "_RawBasicBlock.json"
        fd = codecs.open(file_path,'wb',encoding='utf-8')

	branch_file_path = input_result_file_path + input_result_file_name + "_BranchInfo.json"
        branch_fd = codecs.open(branch_file_path,'wb',encoding='utf-8')

	FunctionList_list = idautils.Functions()      # get all the functions   
	for CurrentFunctionAddress in FunctionList_list:
		Flags = idc.GetFunctionFlags(CurrentFunctionAddress)
		if( Flags & FUNC_LIB) or ( Flags & FUNC_THUNK):     #not function code
			continue

		CurrentFunction = idaapi.get_func(CurrentFunctionAddress)
		FunctionName = idc.GetFunctionName(CurrentFunctionAddress)
		#print("Current Function:" + FunctionName + " at:" + hex(CurrentFunctionAddress))
		FlowChartList_list = get_flow_chart_with_cache(CurrentFunction)
		for CurrentBasicBlock in FlowChartList_list:
			CurrentAddress = CurrentBasicBlock.startEA
			CurrentBBStartAddress = CurrentBasicBlock.startEA
			#print("current_bb_start:" + hex(CurrentBBStartAddress))
			#print("current_bb_end:" + hex(CurrentBasicBlock.endEA))
			while CurrentAddress < CurrentBasicBlock.endEA:
				CurrentInst = idautils.DecodeInstruction(CurrentAddress)
				if not CurrentInst is None:
					if CurrentInst.itype in CALLS:
						#print("find a call, at:" + hex(CurrentAddress).replace("L",""))
						# This basic block is end
						CurrentBBEndAddress = CurrentAddress + CurrentInst.size
						BasicBlock_dict={}
						BasicBlock_dict["BasicBlockStartAddress"]=hex(CurrentBBStartAddress).replace("L","")
						BasicBlock_dict["BasicBlockJccAddress"] = hex(0).replace("L","")
						BasicBlock_dict["BasicBlockCmpAddress"] = hex(0).replace("L","")
						BasicBlock_dict["BasicBlockEndAddress"]= hex(idc.PrevHead(CurrentBBEndAddress)).replace("L","")
						BasicBlock_dict["BasicBlockFunction"]="ADDR_" + hex(CurrentFunctionAddress).replace("0x","").replace("L","")
			                        BasicBlock_dict["BasicBlockSucceedingBlockAddress"] = hex(idc.PrevHead(CurrentBBEndAddress)+CurrentInst.size).replace("L","")
						
                                                insert_unique_basic_block_info(BasicBlockMap,BasicBlock_dict)
                                                inserted = True
						
						CurrentBBStartAddress = CurrentAddress + CurrentInst.size

				CurrentAddress = CurrentAddress + CurrentInst.size
			#print("Current end:" + hex(CurrentAddress))	
			# reach the end
			
			CurrentBBEndAddress = CurrentAddress
			if CurrentBBEndAddress == CurrentBasicBlock.endEA and CurrentBBStartAddress != CurrentBasicBlock.endEA:
				BasicBlock_dict={}
				BasicBlock_dict["BasicBlockStartAddress"]=hex(CurrentBBStartAddress).replace("L","")
				CurrentInstAddress = idc.PrevHead(CurrentBasicBlock.endEA)
				CurrentInst = idautils.DecodeInstruction(CurrentInstAddress)
				
				if CurrentInst.itype in COND_BRANCHES:
					BasicBlock_dict["BasicBlockJccAddress"] = hex(idc.PrevHead(CurrentBasicBlock.endEA)).replace("L","")
					PrevInstruction = idc.PrevHead(idc.PrevHead(CurrentBasicBlock.endEA))
					VirtualCMPInst = idautils.DecodeInstruction(PrevInstruction)
					if VirtualCMPInst.itype in CMPS:
						BasicBlock_dict["BasicBlockCmpAddress"] = hex(PrevInstruction).replace("L","")
					else:
						BasicBlock_dict["BasicBlockCmpAddress"] = hex(0).replace("L","")
						#print("unrecognized instruction at:" + hex(PrevInstruction))
					branch_info, branch_false_info = build_branch_info(CurrentBBStartAddress, CurrentBasicBlock, CurrentInst)
                                        if branch_info is not None:
						Branch_list.append(branch_info)
						Branch_list.append(branch_false_info)
				else:
					BasicBlock_dict["BasicBlockJccAddress"] = hex(0).replace("L","")
					BasicBlock_dict["BasicBlockCmpAddress"] = hex(0).replace("L","")
				BasicBlock_dict["BasicBlockEndAddress"]= hex(idc.PrevHead(CurrentBasicBlock.endEA)).replace("L","")
			        BasicBlock_dict["BasicBlockSucceedingBlockAddress"] = hex(idc.PrevHead(CurrentBasicBlock.endEA)+CurrentInst.size).replace("L","")
				BasicBlock_dict["BasicBlockFunction"]="ADDR_" + hex(CurrentFunctionAddress).replace("0x","").replace("L","")
                                insert_unique_basic_block_info(BasicBlockMap,BasicBlock_dict)
					#print(BasicBlock_dict)
		#print("======================================Function End========================================================")

        BasicBlockList_list = BasicBlockMap.values()
			
	BasicBlockList_list.sort(key=lambda k: (k.get('BasicBlockStartAddress', 0)))
	FileContent_dict["BasicBlocks"]=BasicBlockList_list
	FileContent_dict["BasicBlockCount"]=len(BasicBlockList_list)
	#json.dump(FileContent_dict,fd)
	fd.write(json.dumps(FileContent_dict,sort_keys=True, indent=4, separators=(',', ':')))
	fd.close()
	print("Process RAW Basic Block OK")

	BranchFileContent_dict = {}
	Branch_list.sort(key=lambda k: (k.get('BranchBasicBlock', 0)))
	BranchFileContent_dict["Branch"]=Branch_list
	BranchFileContent_dict["BranchCount"]=len(Branch_list)
	branch_fd.write(json.dumps(BranchFileContent_dict,sort_keys=True, indent=4, separators=(',', ':')))
	branch_fd.close()

def init_error_log(input_result_file_path , input_result_file_name):
    global error_logfile
    error_filepath = input_result_file_path + input_result_file_name + "_log.txt"
    error_logfile = codecs.open(error_filepath,'wb',encoding='utf-8')

def build_branch_info(CurrentBBStartAddress, CurrentBasicBlock, CurrentInst):
    global error_logfile
    branch_inst_addr = CurrentBasicBlock.endEA-CurrentInst.size
    targets_list = list(idautils.CodeRefsFrom(branch_inst_addr, False))
    if len(targets_list) == 0:
        err_line = "no target for branch@%x" % (branch_addr)
        print (err_line)
        error_logfile.write(err_line + "\n")
        return None,None
    #print (targets_list)
    
    branch_info = {}
    branch_info['BranchBasicBlock'] = "BB_" + hex(CurrentBBStartAddress).replace("L","")[2:]
    branch_info['TargetBasicBlock'] = "BB_" + hex(targets_list[0]).replace("L","")[2:]
    branch_info['BranchInstruction'] = "ADDR_" + hex(branch_inst_addr).replace("L","")[2:]
    branch_info['ConditionIsTrue'] = "1"
    #Branch_list.append(branch_info)
    branch_info_false = {}
    branch_info_false['BranchBasicBlock'] = "BB_" + hex(CurrentBBStartAddress).replace("L","")[2:]
    branch_info_false['TargetBasicBlock'] = "BB_" + hex(CurrentBasicBlock.endEA).replace("L","")[2:]
    branch_info_false['BranchInstruction'] = "ADDR_" + hex(branch_inst_addr).replace("L","")[2:]
    branch_info_false['ConditionIsTrue'] = "0"
    #Branch_list.append(branch_info_false)
    return branch_info,branch_info_false


'''
	FunctionName:

	Argument:

	Result:

	Comment:
		
'''
def main():
	#get_func_attribute(functionAttrPath,file_name)
	global g_xrefInformationList_list
        global g_sectionList_list
	global g_raw_xref_map

        idc.Wait()

	g_ModuleImportFunctionNameList_list = []
	g_sectionList_list                  = []
	g_xrefInformationList_list          = []
	g_raw_xref_map                      = {}

#if idc.GetLongPrm(idc.INF_FILETYPE) == idc.FT_ELF:
#	print("Linux ELF File")
        # config all the paths

        disassembledFileName = idaapi.get_root_filename()
        miscOutputPath = "./output/" + disassembledFileName + "/"
        controlFlowGraphInformationFilePath = miscOutputPath + "/CFG/"
        callGraphInformationFilePath = miscOutputPath + "/CG/"

        print("---------------------------------------------------------------------------------------------------------------------------------------------------")
        
        if not os.path.exists(miscOutputPath):
                os.makedirs(miscOutputPath)

        if not os.path.exists(controlFlowGraphInformationFilePath):
                os.makedirs(controlFlowGraphInformationFilePath)

        if not os.path.exists(callGraphInformationFilePath):
                os.makedirs(callGraphInformationFilePath)

        starttime = datetime.datetime.now()
        init_error_log( miscOutputPath , disassembledFileName )

        # generate function information
        get_function_information( miscOutputPath , disassembledFileName )
        function_get_time = datetime.datetime.now()
        print("Function info using time " + str((function_get_time - starttime).seconds))

        # generate section information, ok
        get_section_information( miscOutputPath , disassembledFileName )
        section_get_time = datetime.datetime.now()
        print("Section info using time " + str((section_get_time - function_get_time).seconds))
        
        get_raw_xref_information( miscOutputPath , disassembledFileName )
        xref_get_time = datetime.datetime.now()
        print("XREF info using time " + str((xref_get_time - section_get_time).seconds))

        # generate control flow graph file
        get_control_flow_graph( controlFlowGraphInformationFilePath )
        cfg_get_time = datetime.datetime.now()
        print("CFG info using time " + str((cfg_get_time - xref_get_time).seconds))
        
        # generate raw call graph, 
        get_raw_call_graph( callGraphInformationFilePath , disassembledFileName )
        cg_get_time = datetime.datetime.now()
        print("CG using time " + str((cg_get_time - cfg_get_time).seconds))

        # generate raw basic block record, ok
        get_raw_basic_block_information( miscOutputPath , disassembledFileName )
        endtime = datetime.datetime.now()
        print("BasicBlock info using time " + str((endtime - cg_get_time).seconds))
        
        print( "Using Time:"+ str((endtime - starttime).seconds))
        print("Dump finished")
        # idc.Exit(0)
#else:
#	print("not suitable file type")

if __name__ == '__main__':
    try:
        main()
    except:
        traceback.print_exc()
        print 'Error occured'
