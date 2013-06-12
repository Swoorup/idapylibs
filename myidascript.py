import imp
import struct

#there is always a register in floating point operations
#fld 1212 = fld st, 1212
#st = 0
#1212 = 1
#so for floating point always consider instruction starting at 1
#values for fpu registers are always -1 with GetOperandValue
search = imp.load_source('search', 'D:\\modding\\search.py')
filter = imp.load_source('filter', 'D:\\modding\\filter.py')

keys = [31, 29, 32, 15, 16, 17]
found = search.Search()
found.SetSignedCharSearchValues(keys)


fil = filter.Filter(found.SearchBytesInFunctions("WaterLevel"))
fil.EnableOperandTypeFilter()
fil.SetOperandTypes(5)
fil.EnableMatchingOperand()
fil.SetSignedCharmatchingopvalues(keys)
fil.SetDiscardOperandKeywordsForMatchedOperands("[")
fil.SetDiscardDisasmKeywords("add     esp", "retn", "sub     esp, 10h");
b = fil.GetFilter()
b = [x for x in b if not "CreateWavyAtomic" in GetFunctionName(x)]
b = [x for x in b if not "CalcWavySector" in GetFunctionName(x)]
b = [x for x in b if not "RenderOneFlat" in GetFunctionName(x)]


for i in b:
    print(hex(i) + " " + GetDisasm(i) + GetFunctionName(i))