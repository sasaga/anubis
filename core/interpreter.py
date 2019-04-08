#!/usr/bin/env python
# -*- coding: utf-8 -*-
#autor samir sanchez garnica @sasaga92

import os,sys,re,string
from utilities.colors import * # import utilites.color
import pefile, peutils,magic, hashlib
import time
from collections import namedtuple


class interpreter(object):
	"""docstring for interpreter"""
	
	def fingerprinting(self, _pe_file):
		_info = {}
		_info['size'] = (os.path.getsize(_pe_file))/1000 ,"KB"
		_deter_file = magic.from_file(_pe_file)
		_info['type file'] = _deter_file
		
		with open(_pe_file, 'rb') as f:
			_file  = f.read()
			_info['hash sha1'] = hashlib.sha1(_file).hexdigest()
			_info['hash sha256'] = hashlib.sha256(_file).hexdigest()

			_md5 = hashlib.md5()
			for i in range(0, len(_file), 8192):
				_md5.update(_file[i:i+8192])
			_info['hash md5'] = _md5.hexdigest()
		_pe_file = pefile.PE(_pe_file)
		_compile_date = _pe_file.FILE_HEADER.TimeDateStamp
		_info['compile date'] = str(time.strftime("%Y-%m%d %H:%M:%S",time.localtime(_compile_date)))
		_info['is probably packed'] = peutils.is_probably_packed(_pe_file)
		return _info

	def get_directory_imports(self, _pe_file):
		_file = pefile.PE(_pe_file)
		_file.parse_data_directories()
		print(script_colors("green", "[+]") + " " + script_colors("lgray","Inspecting Files and dependencies Imports"))
		for entry in _file.DIRECTORY_ENTRY_IMPORT:
			print(script_colors("yellow","[!]")+ " "+script_colors("blue",entry.dll.decode('ascii')))
			for imp in entry.imports:
				print("\t"+ script_colors("green",hex(imp.address))+" " +script_colors("lgray",imp.name.decode('ascii')))
	def section_inspection(self, _pe_file):
		print('\t')
		print(script_colors("green", "[+]") + " " + script_colors("lgray","Listing the sections"))
		_file = pefile.PE(_pe_file)
		for section in _file.sections:
		    print(script_colors("green",section.Name.decode('utf-8')))
		    print(script_colors("yellow","\tVirtual Address: ") + script_colors("lgray",hex(section.VirtualAddress)))
		    print(script_colors("yellow","\tVirtual Size: ") + script_colors("lgray",hex(section.Misc_VirtualSize)))
		    print(script_colors("yellow","\tRaw Size: ") + script_colors("lgray",hex(section.SizeOfRawData)))

	def ascii_strings(self,buf, n=4):
		ASCII_BYTE = " !\"#\$%&\'\(\)\*\+,-\./0123456789:;<=>\?@ABCDEFGHIJKLMNOPQRSTUVWXYZ\[\]\^_`abcdefghijklmnopqrstuvwxyz\{\|\}\\\~\t"
		String = namedtuple("String", ["s", "offset"])
		
		reg = "([%s]{%d,})" % (ASCII_BYTE, n)
		ascii_re = re.compile(reg)
		for match in ascii_re.finditer(buf):
			yield String(match.group().decode("ascii"), match.start())
	
	def check_security(self,_pe_file):
		if os.path.isfile(_pe_file):
			dll = pefile.PE(_pe_file)
		print(script_colors("green", "[+]") + " " + script_colors("lgray","check file security ASLR,DEP,SafeSEH"))

		print(script_colors("yellow","\tASLR: ") + script_colors("lgray",str(dll.OPTIONAL_HEADER.IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE)))
		print(script_colors("yellow","\tDEP: ") + script_colors("lgray",str(dll.OPTIONAL_HEADER.IMAGE_DLLCHARACTERISTICS_NX_COMPAT)))
		print(script_colors("yellow","\tSafeSEH: ") + script_colors("lgray",str(dll.OPTIONAL_HEADER.IMAGE_DLLCHARACTERISTICS_NO_SEH)))
		print(script_colors("yellow","\tControlFlowGuard: ") + script_colors("lgray",str(dll.OPTIONAL_HEADER.IMAGE_DLLCHARACTERISTICS_GUARD_CF)))
		print(script_colors("yellow","\tHighentropyVA: ") + script_colors("lgray",str(dll.OPTIONAL_HEADER.IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA)))
			

	def processing_dict(self, _dict):
		for _key, _value in _dict.items():
			print(script_colors("green","[+] ") + script_colors("lgray",_key) +": "+ script_colors("lgray",str(_value)))

