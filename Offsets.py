# Author: Uhrwerk (Inspired by eb's Offsets.py)
# Version: 1.3

# Imports
from idc import BADADDR, INF_BASEADDR, SEARCH_DOWN, FUNCATTR_START, FUNCATTR_END
import idc
import idaapi
import datetime

# Settings
definePrefix = "" # Prefix for the #define Output
functionPrefix = "fn" # Prefix for Function Renaming in IDA
offsetPrefix = "o" # Prefix for Offset Renaming in IDA

# Globals
Rename = -1

# Offsets // Patterns // xref's (Type:: 1 => Pattern, 2 => Call Pattern, 3 => Reference)
Functions = [
	["IssueOrder", "81 EC ? ? ? ? 53 8B D9 C7 44 24", 1],
	["Logger", "8D 44 24 14 50 FF 74 24 14 FF", 1], # Writes Debug Messages (Also printed when you attach VS Debugger)
	["CastSpell", "83 EC 34 53 55 8B 6C 24 40", 1], # ALE-229C053F / ERROR: Client Tried to cast a spell from an invalid slot: %d
	#\x83\xEC\x34\x53\x55\x8B\x6C\x24\x40 xxxxxxxxx
	#\x83\xEC\x2C\x53\x55\x56\x8B\x74\x24\x3C xxxxxxxxxx
	["GetHealthbarPos", "8B 81 ? ? ? ? 85 C0 74 12", 1],	
	#\x8B\x81\x00\x00\x00\x00\x85\xC0\x74\x12 xx????xxxx
	["SendChat", "56 6A FF FF 74", 1],
	#\x56\x6A\xFF\xFF\x74 xxxxx
	["EventHandler", "83 EC 38 A1 ? ? ? ? 33 C4 89 44 24 34 53 8B D9 56 8B 74 24 48", 1],
		
	["DrawTurretRange", "E8 ? ? ? ? 84 C0 75 1B 83", 2],
	#\xE8\x00\x00\x00\x00\x84\xC0\x75\x1B\x83 x????xxxxx
	["LevelUpSpell", "E8 ? ? ? ? A1 ? ? ? ? 85 C0 74 0F 8B", 2],
	#\xE8\x00\x00\x00\x00\xA1\x00\x00\x00\x00\x85\xC0\x74\x0F\x8B x????x????xxxxx
	["SetSkin", "E8 ? ? ? ? 8B 0E 8B F8 8B 87", 2],
	#\xE8\x00\x00\x00\x00\x8B\x0E\x8B\xF8\x8B\x87 x????xxxxxx
	["GetSpellData", "E8 ? ? ? ? 66 85 C0 74 06", 2], # aka. GetSpellState
	#\xE8\x00\x00\x00\x00\x66\x85\xC0\x74\x06 x????xxxxx
	["PrintChat", "E8 ? ? ? ? C6 44 24 ? ? 85 DB 74 76 8D 44 24 14", 2], 
	#\xE8\x00\x00\x00\x00\xC6\x44\x24\x00\x00\x85\xDB\x74\x76\x8D\x44\x24\x14 x????xxx??xxxxxxxx
	["MainLoop", "E8 ? ? ? ? E8 ? ? ? ? 85 C0 74 07 8B 10 8B C8 FF 52", 2], # Not directly the main loop, but you can hook into here (func called by the main loop)
	#\xE8\x00\x00\x00\x00\xE8\x00\x00\x00\x00\x85\xC0\x74\x07\x8B\x10\x8B\xC8\xFF\x52 x????x????xxxxxxxxxx
	
	#["ClientMain", "Invalid AttackDelayCastOffsetPercent!", 3]
]

Offsets = [
	["LocalPlayer", "3B 35 ? ? ? ? 75 51", 1, 1], # Node <%s> tried to get Player (above three nodes, mov eax LocalPlayer)
	#\x3B\x35\x00\x00\x00\x00\x75\x51 xx????xx
	["ChatClientPtr", "A1 ? ? ? ? 85 C0 74 32", 1, 1],
	#\xA1\x00\x00\x00\x00\x85\xC0\x74\x32 x????xxxx
	["ObjectManager", "A1 ?? ?? ?? ?? 8B 0C 88 85 C9 74 0E 39 71 08 75 09 6A 01", 1, 1], # ALE-DFB7B379 (below mov eax, ObjectManager)
	["Renderer", "A1 ? ? ? ? 6A 00 6A 00 8B B0", 1, 1], # SkinnedMesh_SOLID_COLOR_PS (above mox ecx, Renderer) / %1_WEIGHT%2 (below call sub .. mov ecx, Renderer)
	
	["ZoomClass", "A3 ? ? ? ? 8D 4C 24 20", 1, 0], # Globals/CameraConfig_CLASSIC (above cmp ZoomBase, 0)
	["UnderMouseObject", "C7 05 ? ? ? ? ? ? ? ? E8 ? ? ? ? 83 C4 04 FF B4", 1, 0],
	#\xC7\x05\x00\x00\x00\x00\x00\x00\x00\x00\xE8\x00\x00\x00\x00\x83\xC4\x04\xFF\xB4 xx????????x????xxxxx
	
	["Version", "68 ? ? ? ? E8 ? ? ? ? 83 C4 20 8D 4C 24 04", 2, 0],# "Version %s (%s/%s) [%s] <%s>%s"
]

# Finder Functions
def FindFuncPattern(Pattern): # Find's Func. by Pattern
	addr = idc.FindBinary(0, SEARCH_DOWN, Pattern)
	if addr == BADADDR: return 0
	
	try:
		return idaapi.get_func(addr).startEA
	except Exception:
		return 0
		
def FindFuncCall(Pattern): # Find's Func. by Pattern to a Call
	addr = idc.FindBinary(0, SEARCH_DOWN, Pattern)
	if addr == BADADDR: return 0
	return idc.GetOperandValue(addr, 0)
	
def FindFuncFirstReference(Reference): # Find's Func. by Reference, Returns first 
	addr = idc.FindBinary(0, SEARCH_DOWN, "\"" + Reference + "\"")
	if addr == BADADDR: return 0
	
	dword = -1
	xrefs = XrefsTo(addr)
	for xref in xrefs:
		dword = xref.frm
		
	try:
		return idaapi.get_func(dword).startEA
	except Exception:
		return 0

def FindStringByReference(Reference): # Extracts String out of Reference (//addr)
	addr = idc.FindBinary(0, SEARCH_DOWN, "\"" + Reference + "\"")
	if addr == BADADDR: return 0
	return idc.GetString(addr)
	
def FindOffsetPattern(Pattern, Operand): # Find Offset by Pattern
	addr = idc.FindBinary(0, SEARCH_DOWN, Pattern)
	if addr == BADADDR: return 0
	
	return idc.GetOperandValue(addr, Operand)
	
# Helpers
def DecToHex(Addr):
	return "0x%0.2X" % Addr
	
def PrintWrapper(Alias, Addr, Type): # Type: 1 => Function, 2 => Offset
	if Addr == BADADDR or Addr == 0 or Addr == 0x00:
		print(Alias + " -> Error")
		return
		
	if Type == 1: print("#define " + functionPrefix + Alias + " " + DecToHex(Addr))
	if Type == 2: print("#define " + offsetPrefix + Alias + " " + DecToHex(Addr))
	
	if Rename == 1:
		if Type == 1: MakeName(Addr, str(functionPrefix + Alias))
		if Type == 2: MakeName(Addr, str(offsetPrefix + Alias))
		
	return
	
# Main
def Initialize():
	global Rename
	Rename = idc.AskYN(0, "Automaticly Update Names? (sub_549570 => PrintChat)")
	if Rename == -1:
		print("Exiting...")
		return
		
	print("")
	print("++ Uhrwerk: Offsets (%s)" % datetime.datetime.now())
	print("Why do they keep breaking...")
	print("")
	
	print("++ Functions")
	for Alias, Reference, Type in Functions:
		if Type == 1: PrintWrapper(Alias, FindFuncPattern(Reference), 1)
		if Type == 2: PrintWrapper(Alias, FindFuncCall(Reference), 1)
		if Type == 3: PrintWrapper(Alias, FindFuncFirstReference(Reference), 1)
	print("")
	
	print("++ Offsets")
	for Alias, Reference, Type, Operand in Offsets:
		if Type == 1: PrintWrapper(Alias, FindOffsetPattern(Reference, Operand), 2)
		if Type == 2: PrintWrapper(Alias, FindOffsetPattern(Reference, Operand), 2)
	print("")
	
Initialize()