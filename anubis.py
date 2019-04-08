#!/usr/bin/env python
# -*- coding: utf-8 -*-
#autor samir sanchez garnica @sasaga92

from core.banner import Banner
import argparse
from core.interpreter import *
import re

def main():
	_parser = argparse.ArgumentParser(prog='anubis',usage='python3 anubis.py [options]',  add_help=False)
	help_arguments = _parser.add_argument_group('help arguments')
	help_arguments.add_argument('-v', '--version', action='version', version="version 1.0")
	help_arguments.add_argument('-h', '--help', action='help', default=argparse.SUPPRESS, help='Show a help message.')


	
	_parser = argparse.ArgumentParser()
	_parser.add_argument("--file", dest="file", help="binary path to analyze", required=False)


	_args = _parser.parse_args()

	Banner()
	
	try:
		if len(_args.file) > 0 :
			_get_info = interpreter().fingerprinting(_args.file)
			interpreter().processing_dict(_get_info)
			interpreter().check_security(_args.file)
			interpreter().section_inspection(_args.file)
			interpreter().get_directory_imports(_args.file)

			with open(_args.file, 'rb') as f:
				b = f.read()


			print(script_colors("yellow","[!]")+ " "+script_colors("blue","interesting metadata!"))
			_exte = ['exe','doc','docx','xls','xlsx','xml','txt','jpg','mov','bmp','mp3', 'cry','crypto','CriptoLocker2015','darkness','enc','exx','kb15','kraken','locked','nochance','___xratteamLucked','__AiraCropEncrypted!','_AiraCropEncrypted','_read_thi$_file','02','0x0','725','1btc','1999','1cbu1','1txt','2ed2','31392E30362E32303136_[ID-KEY]_LSBJ1','73i87A','726','777','7h9r','7z.encrypted','7zipper','8c7f','8lock8','911','a19','a5zfn','aaa ','abc ','adk','adr','AES','AES256 ','aes_ni','aes_ni_gov','aes_ni_0day ','AESIR','AFD','aga','alcatraz','Aleta','amba','amnesia','angelamerkel','AngleWare','antihacker2017','animus','ap19','atlas','aurora','axx','B6E1','BarRax','barracuda','bart','bart.zip','better_call_saul','bip','birbb','bitstak','bitkangoroo','boom','black007','bleep','bleepYourFiles ','bloc','blocatto','block','braincrypt','breaking_bad','bript','brrr','btc','btcbtcbtc','btc-help-you','cancer','canihelpyou','cbf','ccc','CCCRRRPPP','cerber','cerber2','cerber3','checkdiskenced','chifrator@qq_com ','CHIP ','cifgksaffsfyghd','clf','cnc','code','coded','comrade','coverton','crashed','crime','crinf','criptiko ','crypton','criptokod ','cripttt ','crjoker','crptrgr','CRRRT ','cry','cry_','cryp1 ','crypt','crypt38','crypted','cryptes','crypted_file','crypto','cryptolocker','CRYPTOSHIEL','CRYPTOSHIELD','CryptoTorLocker2015!','cryptowall','cryptowin','crypz','CrySiS','css','ctb2','ctbl','CTBL','czvxce','d4nk','da_vinci_code','dale','damage','darkness ','darkcry','dCrypt','decrypt2017','ded','deria','desu','dharma','disappeared','diablo6','divine','doubleoffset','domino','doomed','dxxd','dyatel@qq_com','ecc','edgel','enc','encedRSA','EnCiPhErEd','encmywork','encoderpass','ENCR','encrypt','encrypted','EnCrYpTeD','encryptedAES','encryptedRSA','encryptedyourfiles','enigma','epic','evillock','exotic','exte','exx','ezz','fantom','fear','FenixIloveyou!!','file0locked','filegofprencrp','fileiscryptedhard','filock','firecrypt','flyper','frtrss','fs0ciety','fuck','Fuck_You','fucked','FuckYourData ','fun','gamma','gefickt','gembok','globe','glutton','goforhelp','good','gruzin@qq_com ','gryphon','GSupport','GWS','HA3','hairullah@inbox.lv','hakunamatata','hannah','haters','happyday ','happydayzz','happydayzzz','hb15','helpdecrypt@ukr.net','helpmeencedfiles','herbst','help','hnumkhotep','hitler','howcanihelpusir','html','hush','hydracrypt','iaufkakfhsaraf','ifuckedyou','iloveworld','infected','info','invaded','isis ','ipYgh','iwanthelpuuu','jaff','java','JUST','justbtcwillhelpyou','JLQUF','karma','kb15','kencf','keepcalm','kernel_complete','kernel_pid','kernel_time','keybtc@inbox_com','KEYH0LES','KEYZ ','eemail.me','killedXXX','kirked','kimcilware','KKK','kk','korrektor','kostya','kr3','krab','kraken','kratos','kyra','L0CKED','L0cked','lambda_l0cked','LeChiffre','legion','lesli','letmetrydecfiles','letmetrydecfiles','like','lock','lock93','locked','Locked-by-Mafia','locked-mafiaware','locklock','locky','LOL!','loprt','lovewindows','lukitus','madebyadam','magic','maktub','malki','maya','merry','micro','MRCR1','nalog@qq_com','nemo-hacks.at.sigaint.org','nobad','no_more_ransom','nochance','nochance ','nolvalid','noproblemwedecfiles','notfoundrans','nuclear55','uclear','obleep','odcodc','odin','OMG!','only-we_can-help_you','onion.to._','oops','openforyou@india.com','oplata@qq.com ','oshit','osiris','otherinformation','oxr','p5tkjw','pablukcrypt','padcrypt','paybtcs','paym','paymrss','payms','paymst','paymts','payransom','payrms','payrmts','pays','paytounlock','pdcr','PEGS1','perl','pizda@qq_com','PoAr2w','porno','potato','powerfulldecrypt','powned','pr0tect','purge','pzdc','R.i.P','r16m','R16M01D05','r3store','R4A ','R5A','r5a','RAD ','RADAMANT','raid10','ransomware','RARE1','rastakhiz','razy','RDM','rdmk','realfs0ciety@sigaint.org.fs0ciety','rekt','relock@qq_com','reyptson','remind','rip','RMCM1','rmd','rnsmwr','rokku','rrk','RSNSlocked ','RSplited','sage','salsa222','sanction','scl','SecureCrypted','serpent','sexy','shino','shit','sifreli','Silent','sport','stn','supercrypt','surprise','szf','t5019','tedcrypt','TheTrumpLockerf','thda','TheTrumpLockerfp','theworldisyours','thor','toxcrypt','troyancoder@qq_com','trun','trmt','ttt','tzu','uk-dealer@sigaint.org','unavailable','unlockvt@india.com','vault','vbransom','vekanhelpu','velikasrbija','venusf','Venusp','versiegelt','VforVendetta','vindows','viki','visioncrypt','vvv','vxLock','wallet','wcry','weareyourfriends','weencedufiles','wflx','wlu','Where_my_files.txt','Whereisyourfiles','windows10','wnx','WNCRY','wncryt','wnry','wowreadfordecryp','wowwhereismyfiles','wuciwug','www','xiaoba','xcri','xdata','xort','xrnt','xrtn','xtbl','xyz','ya.ru','yourransom','Z81928819','zc3791','zcrypt','zendr4','zepto','zorro','zXz','zyklon','zzz ','zzzzz','gmail_com_','india.com','crypt ','H_e_l_p_RECOVER_INSTRUCTIONS','LAST','nullbyte','READ_THIS_FILE_','BCXYZ11','pyt','rypt','ecipher','mail.crypt','elp_restore.','elp_your_files.','ow_to_recover.','nstall_tor.','eemail.me','q_com','estore_fi.','kr.net','ant your files back.','rypt','ECRYPT_INFO_','ocky_recover_instructions.txt','yp','ecret_code.txt','lFilesAreLocked.bmp','SISTANCE_IN_RECOVERY.txt','TENTION!!!.txt','nfirmation.key','crypt.exe','CRYPT_INSTRUCTION.HTML','CRYPT_INSTRUCTION.TXT','CRYPT_INSTRUCTIONS.HTML','CRYPT_INSTRUCTIONS.TXT','cryptAllFiles.txt','cryptAllFiles.txt','c_files.txt','LP_DECRYPT.HTML','LP_DECRYPT.lnk','LP_DECRYPT.PNG','LP_DECRYPT.TXT','LP_RESTORE_FILES.txt','LP_TO_DECRYPT_YOUR_FILES.txt','LP_TO_SAVE_FILES.txt','w to decrypt aes files.lnk','w_Decrypt.html','w_Decrypt.txt','wDecrypt.txt','wrecover+.txt','wto_recover_file.txt','MREADYTOPAY.TXT','STRUCCIONES_DESCIFRADO.TXT','st_chance.txt','ssage.txt','SSAGE.txt','r.','covery_file.txt','covery_key.txt','COVERY_KEY.TXT','store_files.txt','store_files.txt','ult.hta','ult.key','ult.txt','UR_FILES.HTML','UR_FILES.url']
			_regedit = ['HKLM','HKCR','HKU','HKCU','HKEY_LOCAL_MACHINE','HKEY_CLASSES_ROOT','HKEY_USERS','HKEY_CURRENT_USER','HKEY_PERFORMANCE_DATA','HKEY_DYN_DATA','SOFTWARE','command','CurrentVersion']
			_result = []

			regex = r'[\w.%+-]+'
			
			for s in interpreter().ascii_strings(b):
				fil = s.s
				file_ext = fil.split('.')[-1] if len(fil.split('.')) > 1 else None
				extensions = [ext.replace('.', '') for ext in _exte]
				if file_ext in extensions:
					print(script_colors("yellow",'\t0x{:x}:').format(s.offset)+script_colors("lgray",'{:s}').format(s.s))
				for calls in _regedit:
					if re.findall(calls, s.s):
						_result.append(script_colors("yellow",'\t0x{:x}:').format(s.offset)+script_colors("lgray",'{:s}').format(s.s))
				
				
				if re.findall(regex,s.s):
					if not s.s in _regedit and not s.s in _exte:
						_result.append(script_colors("yellow",'\t0x{:x}:').format(s.offset)+script_colors("lgray",'{:s}').format(s.s))

			for _find in set(_result):
				print(_find)

		else:
				print("opcion no encontrada/..")
	except Exception as e:
		print("debes digitar por lo menos una opcion")



if __name__ == '__main__':
	main()
