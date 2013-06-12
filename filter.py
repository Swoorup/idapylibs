import find
import struct
import itertools

from idautils import *
from idaapi import *
from idc import *

#S_OPERAND_TYPE = enum(
# do not filter strings
class Filter(object):
	def debugprint(self, debugstr):
		print(debugstr)
		
	def __init__(self, addrs):
		self.bperformsearch = False

		#by default search for immediate, addresses, displacements
		self.operandtypes = range(1, 7 + 1)
		self.bmatchoperand = False
		self.matchingopvalues = []
		self.addresses = addrs
		self.discardmatchop = []
		
	def SetAddresses(self, addrs):
		self.addresses = addrs	
		
	def EnableOperandTypeFilter(self):
		self.boperandtypeFilter = True
		
	def DisableOperandTypeFilter(self):
		self.boperandtypeFilter = False
		
	def EnableMatchingOperand(self):
		self.bmatchoperand = True
		
	def DisableMatchingOperand(self):
		self.bmatchoperand = False
	
	def SetOperandTypes(self, optypes):
		if not isinstance(optypes, list):
			optypes = [optypes]
		self.operandtypes = optypes
		
	def SetSignedCharmatchingopvalues(self, matchingopvalues):
		self.debugprint(matchingopvalues)
		if not isinstance(matchingopvalues, list):
			matchingopvalues = [matchingopvalues]
		self.matchingopvalues = [struct.pack('<b', x) for x in matchingopvalues]
		
	def SetFloatmatchingopvalues(self, matchingopvalues):
		matchingopvalues = [matchingopvalues] if not isinstance(matchingopvalues, list) else 0
		self.matchingopvalues = [struct.pack('<f', x) for x in matchingopvalues]
	
	def SetDiscardOperandKeywordsForMatchedOperands(self, *discards):
		self.discardmatchop = [x for x in discards]
	
	def SetDiscardDisasmKeywords(self, *discards):
		self.discarddisasm = [x for x in discards]
		
	#TO DO
	#cleanup bool before its dirty
	def GetFilter(self):
		#first enumerate the data
		
		foundaddr = []
		for addr in self.addresses:
			if SegName(addr) == ".text":
				for val in self.matchingopvalues:
					#self.debugprint(self.searchval)
					#self.debugprint(hex(addr) + " " + str(ord(val)))
					if not addr in foundaddr:
						inst = ItemHead(addr)
						
						discard = False
						for d in self.discarddisasm:
							if d in GetDisasm(addr):
								discard = True 
								break
							else:
								discard = False
									
						if discard == True: continue
						if GetOpType(inst, 0) in self.operandtypes or GetOpType(inst, 1) in self.operandtypes:
							op1 = GetOperandValue(inst, 0)
							op2 = GetOperandValue(inst, 1)
							v = struct.unpack_from('b', val[0])
							#print op1
							#print op2
							#print v
							if self.bmatchoperand:
								discard = False
								if (op1 == v[0]):
									for d in self.discardmatchop:
										if d in GetOpnd(inst, 0):
											discard = True 
											break
										else:
											discard = False
											
									if discard == False: foundaddr.append(addr)
								discard = False
								if (op2 == v[0]):
									for d in self.discardmatchop:
										if d in GetOpnd(inst, 1):
											discard = True 
											break
										else:
											discard = False
											
									if discard == False: foundaddr.append(addr)
							else:
								foundaddr.append(addr)
			else:
				foundaddr.append(addr)
				
		
		
		return foundaddr
				