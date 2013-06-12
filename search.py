# self.searchstr must be a list of strings
"""
examples: 
self.searchstr = '\xDE\xAD\xBE\xEF'
self.searchstr = ["DEADBEEF".decode("hex")]
self.searchstr = [struct.pack("f", 2048), struct.pack("f", 400)]
self.searchstr = ["AUDIO"]
print(struct.pack('<I', 2863349888).encode('hex'))
print(struct.pack('<f', 2048).encode('hex'))

TODO

Need to also handle endianess for searchchar, searchfloats, etc
"""

from idautils import *
from idaapi import *
from idc import *
import binascii
import itertools

class Search(object):
#we usually consider data size as ida might not correctly detect them
#we don't consider instruction size
	def __init__(self, ConsiderinstructionItem=True, ConsiderDataItem=False):
		self.considerinstructionItem = ConsiderinstructionItem;
		self.considerDataItem = ConsiderDataItem;
		self.searchstrs = []
	
	def debugprint(self, str):
		print("DEBUG: Search: " + str)
	
	def SearchBytesIn(self, startea, endea):
		foundaddress = []
		self.debugprint("considering searches only between instructions")
		
		if not isinstance(self.searchstrs, list):
			self.searchstrs = [self.searchstrs]
		
		for ea in range(startea, endea):
			for searchterm in self.searchstrs:
				#end_ea = endea - len(searchterm)
				if ea + len(searchterm) > ItemEnd(ea) :
					if SegName(ea) == ".text" and self.considerinstructionItem == False:
						foundaddress.append(ea) if GetManyBytes(ea, len(searchterm)) == searchterm else 0
					elif SegName(ea) == ".data" and self.considerDataItem == False:
						foundaddress.append(ea) if GetManyBytes(ea, len(searchterm)) == searchterm else 0
				else:
					foundaddress.append(ea) if GetManyBytes(ea, len(searchterm)) == searchterm else 0
				
		return foundaddress
	
	def SearchBytesInSegments(self, *segkeyword):
		foundaddress = []
		
		seg_eas = [ea for ea, name in itertools.product(Segments(), segkeyword) if name in SegName(ea)]
		for seg_ea in seg_eas:
			self.debugprint("Found Segment " + SegName(seg_ea))
			foundaddress.extend(self.SearchBytesIn(seg_ea, SegEnd(seg_ea)))	
			
		return foundaddress
		
	def SearchBytesInFunctions(self, *funckeyword):
		foundaddress = []
		
		func_ea = [ea for ea,name in itertools.product(Functions(), funckeyword) if name in GetFunctionName(ea)]
		for startea in func_ea:
			endea = GetFunctionAttr(startea, FUNCATTR_END)
			self.debugprint("Found Function " + GetFunctionName(startea))
			foundaddress.extend(self.SearchBytesIn(startea, endea))
			
		return foundaddress
		
	def SetSearchValues(self, searchvals):
		self.searchstrs = searchvals
		
	def SetSignedCharSearchValues(self, searchvalschars):
		#self.debugprint(searchvalschars)
		if not isinstance(searchvalschars, list):
			searchvalschars = [searchvalschars]
		self.searchstrs = [struct.pack('<b', x) for x in searchvalschars]
		
	def SetFloatSearchValues(self, searchvalfloats):
		searchvalfloats = [searchvalfloats] if not isinstance(searchvalfloats, list) else 0
		self.searchstrs = [struct.pack('<f', x) for x in searchvalfloats]