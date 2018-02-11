# Author: Uhrwerk
# Version: 1.0

# Notes
# Lacking Error Handling
# Possibility to combine with Offset Scanner to dynamicly generate Structures? 

# Imports
import idaapi
import idc

# Functions
def parse_decls(inputtype, flags = 0):
	ret = ida_typeinf.idc_parse_types(inputtype, flags)
	return ret # Error Handling?

def type_to_struct(name):
	idc.del_struc(idc.get_struc_id(name)) # delete existing struct
	idc.import_type(-1, name) # -1 = append to end
	
# Witchcraft
def Main():
	print("Object Definator")
	
	# Object + ObjectManager
	parse_decls("C:\\Reversing\\Uhrwerk\\Information\\ida_structs.h", 0x0001) # 0x0001 = PF_FILE
	type_to_struct("GameObject")
	type_to_struct("GameObjectManager")
	
	# Apply the structures to all found Instances
	
Main()