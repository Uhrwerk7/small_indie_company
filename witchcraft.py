# Author: Uhrwerk
# Version: 1.4

# Notes
# Lacking Error Handling (unlucky people shouldn't use my software i guess)
# Add Missile, Game Modes & Status Effects
# Add Applying Mode
# Automatic Type Deduction would be nice + getting the offset for char/charintermediate automaticly
# fix k, v swapness
# fix types (float) and add types in charintermediate

# Imports
from idc import BADADDR, INF_BASEADDR, SEARCH_DOWN, FUNCATTR_START, FUNCATTR_END
import idc
import idaapi
import idautils
import datetime

# Globals
DumpOrApply = -1 # 0 = Dump, 1 = Apply
DumpType = 1 # 0 = Inheritance, 1 = In-Class

#region Patterns (Pattern, Type(1 = Direct, 2 = Call)) 

# AttackableUnit
au_patterns = [
	["83 EC 0C 53 55 56 8B F1 57 8B 06", 1], # 1 .. FriendlyTooltip
	["E8 ? ? ? ? 8B CF E8 ? ? ? ? 6A 00 68 ? ? ? ?", 2], #2 .. mAllShield
	["E8 ? ? ? ? 5E 5B 83 C4 0C C2 04", 2], #3 .. mGold
]

# Missile Data
md_patterns = [
	["", 1] # 1 .. mAffectsTypeFlags
]

# Unit Data
ud_patterns = [
	["E8 ? ? ? ? 8B 4C 24 3C 8D B5", 2], # 1 .. mPrimaryARRegenRateRep
	["E8 ? ? ? ? 83 C4 3C 8B CB", 2], # 2 .. mMoveSpeedBaseIncrease
	["53 55 8B 6C 24 14 8B CD 56 8B 74 24 14 57 68 98 59 EF 00", 1], # 3 .. mPercentBonusArmorPenetration
	["E8 ? ? ? ? 8B 9E ? ? ? ? 8D BE ? ? ? ? 83 C4 28", 2], # 4 .. mPassiveCooldownTotalTime
]

# Champion Data
cd_patterns = [
	["56 6A 00 6A 00 6A 00 6A 00 6A 08", 1], # .. mCharacterName
]

# Game Modes
# 83 EC 0C 53 56 57 8B 7C 24 1C 8B F1 8B

# Status Effects
# xref Drowsy or Asleep

#endregion

#region Functions
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
	
def is_user_name(ea):
  f = idc.GetFlags(ea)
  return idc.hasUserName(f)

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

def get_values_from_patterns(patterns):
	found_values = {}
	
	for pattern in patterns:
		if pattern[1] == 1: offset = find_func_pattern(pattern[0])
		if pattern[1] == 2: offset = find_func_call_pattern(pattern[0])
		if offset == 0: 
			print("[WARNING]: Invalid Pattern {}").format(pattern[0])
			continue
			
		data = generate_data_from_offset(offset)
		for k, v in data.iteritems():
			if k == -1: continue # Invalid Addr.
			found_values[k] = v
	
	found_values = sorted(found_values.iteritems())

	return found_values

def dec_to_hex(num):
	return "0x%0.2X" % num
#endregion

#region Static
au_class = ""
ud_object_offset = "0xE50"
objmgr_class = ""

# type, size, name
obj_class_static = [

]

#endregion

#region TypeMappings
Types = [
	["int", 4, ["Champion", "mPARState", "mSARState", "mStopShieldFade", "mEvolvePoints", "mEvolveFlag", "mLevelRef", "mNumNeutralMinionsKilled", "mInputLocks", "mHealthBarCharacterIDForIcon"]],
	["bool", 1, ["mPAREnabled", "mSAREnabled", "mIsUntargetableToAllies", "mIsUntargetableToEnemies", "mIsTargetable", "mSkillUpLevelDeltaReplicate"]],
	["char", 1, ["mEmpoweredBitField"]],
]

def get_type_by_name(name):
	for type in Types:
		for identifier in type[2]:
			if name == identifier:
				#print("Found {}").format(name)
				return (type[0], type[1])

	return ("float", 4) # Default
#endregion

# Witchcraft
def Main():
	print("")
	print("Uhrwerk: Witchcraft (%s)" % datetime.datetime.now())
	print("Why do they keep breaking...")
	print("")
	
	#region Dumping
	found_values_au = get_values_from_patterns(au_patterns)
	found_values_ud = get_values_from_patterns(ud_patterns)

	if DumpType == 1:
		#region ObjectData
		obj_class = "class Object\n"
		obj_class += "{\npublic:\n\n"
		#obj_class += "private:\n"

		found_values_obj_ex = {}
		for k, v in found_values_ud: 
			found_values_obj_ex[k + 0xE50] = v
		for k, v in found_values_au:
			found_values_obj_ex[k] = v
		found_values_obj_ex = sorted(found_values_obj_ex.iteritems())

		current_location = 0
		counter = 0
		for k, v in found_values_obj_ex:
			type = get_type_by_name(v)

			obj_class += "\t unsigned char Padding{}[{}]; // {}\n".format(counter, dec_to_hex(k - current_location), dec_to_hex(current_location))
			obj_class += "\t {} {}; // {}\n".format(type[0], v, dec_to_hex(k))

			current_location = k + type[1]
			counter += 1

		obj_class += "};"
		print(obj_class)
		print("")
		#endregion

		found_values_cd = get_values_from_patterns(cd_patterns)

		for k, v in found_values_cd:
			print("{} : {}").format(v, dec_to_hex(k))

	#endregion

	# Write to File
	
	# Object + ObjectManager
	#parse_decls("C:\\Reversing\\Uhrwerk\\Information\\ida_structs.h", 0x0001) # 0x0001 = PF_FILE
	#type_to_struct("GameObject")
	#type_to_struct("GameObjectManager")
	
Main()