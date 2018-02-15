# Author: Uhrwerk
# Version: 1.0

# Notes
# Lacking Error Handling

# Imports
from idc import BADADDR, INF_BASEADDR, SEARCH_DOWN, FUNCATTR_START, FUNCATTR_END
import idc
import idaapi
import datetime

# Patterns (Pattern, Type(1 = Direct, 2 = Call)) 

# AttackableUnit
au_patterns = [
	["83 EC 0C 53 55 56 8B F1 57 8B 06", 1], # 1 .. FriendlyTooltip
	["E8 ? ? ? ? 8B CF E8 ? ? ? ? 6A 00 68 ? ? ? ?", 2], #2 mAllShield
	["E8 ? ? ? ? 5E 5B 83 C4 0C C2 04", 2], #3 mGold
]

# Functions
def parse_decls(inputtype, flags = 0):
	ret = ida_typeinf.idc_parse_types(inputtype, flags)
	return ret # Error Handling?

def type_to_struct(name):
	idc.del_struc(idc.get_struc_id(name)) # delete existing struct
	idc.import_type(-1, name) # -1 = append to end
	
def pattern_scan(pattern):
	addr = idc.FindBinary(0, SEARCH_DOWN, pattern)
	if addr == BADADDR: return 0
	return addr

def find_func_pattern(pattern): # Direct Function Pattern
	addr = idc.FindBinary(0, SEARCH_DOWN, pattern)
	if addr == BADADDR: return 0

	try:
		return idaapi.get_func(addr).startEA
	except exception:
		return 0
		
def find_func_call_pattern(pattern): # Call to Function
	addr = idc.FindBinary(0, SEARCH_DOWN, pattern)
	if addr == BADADDR: return 0
	return idc.GetOperandValue(addr, 0)

def generate_data_from_offset(offset): # credits to ferhat, or whoever wrote this
	found_values = {}
	chunks = idautils.Chunks(offset)
	for begin, end in chunks:
		name = ""
		offset = -1
		ea = begin

		while ea != end:
			mnem = idc.GetMnem(ea)
			opnd = idc.GetOpnd(ea, 0)
			stack_value = idc.GetOperandValue(ea, 0)

			if mnem == "jz" or mnem == "jl":
				name = ""
				offset = -1

			if offset == -1 and (mnem == "add" or mnem == "lea" or mnem == "sub"):
				offset = idc.GetOperandValue(ea, 1)
				if mnem == "sub":
					offset = 0x100000000 - offset

			if mnem == "push" and "offset" in opnd and "pNodeName" not in opnd:
				name = idc.GetString(stack_value, -1, idc.ASCSTR_C)
				
			if is_user_name(stack_value): # this should crash? wtf
				name = idc.NameEx(idc.BADADDR, stack_value)

			if mnem == "call" or mnem =="jmp":
				#print("{} at {}").format(name, dec_to_hex(offset))
				if name:
					found_values[offset] = name
					name = ""
				offset = -1
	
			ea = idc.NextNotTail(ea)
			
	return found_values
	
def dec_to_hex(num):
	return "0x%0.2X" % num
	
# Witchcraft
def Main():
	print("")
	print("Clockwork: Witchcraft (%s)" % datetime.datetime.now())
	print("Why do they keep breaking...")
	print("")
	
	# Find AttackableUnit Data
	found_values_au = {}
	
	for pattern in au_patterns: 
		if pattern[1] == 1: offset = find_func_pattern(pattern[0])
		if pattern[1] == 2: offset = find_func_call_pattern(pattern[0])
		#print(dec_to_hex(offset))
		
		data = generate_data_from_offset(offset)
		for k, v in data.iteritems():
			if k == -1: continue # Invalid Addr.
			found_values_au[k] = v
	
	found_values_au = sorted(found_values_au.iteritems())
	print(found_values_au)
	
	# Write to File
	
	# Object + ObjectManager
	#parse_decls("C:\\Reversing\\Uhrwerk\\Information\\ida_structs.h", 0x0001) # 0x0001 = PF_FILE
	#type_to_struct("GameObject")
	#type_to_struct("GameObjectManager")
	
Main()