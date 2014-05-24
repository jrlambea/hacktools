#!/usr/bin/python
import sys
import os.path

def main():
	if len(sys.argv) != 2:
		print("Use: ./analfat32.py ${FAT32FILE}")
		sys.exit(1)

	binFile = sys.argv[1]

	print "Fat32FILE " + binFile + " Analysis:"

	if os.path.isfile(binFile):
		f = open(binFile, "rb")

		try:

			BS_jmpBoot = ""
			bBS_jmpBoot = False
			byte = f.read(3)
			for b in byte:
				BS_jmpBoot += hex(ord(b)) + ","
			if ( ord(byte[0]) == 0xeb ) or ( ord(byte[0]) == 0xe9 ):
				bBS_jmpBoot = True
			print( "\tBS_jmpBoot:\t" + BS_jmpBoot[:-1] + " Bootable=" + str(bBS_jmpBoot) )

			BS_OEMName = ""
			sBS_OEMName = ""
			byte = f.read(8)
			for b in byte:
				BS_OEMName += hex(ord(b)) + ","
				sBS_OEMName += b
			print( "\tBS_OEMName:\t" + BS_OEMName[:-1] + " (\"" + sBS_OEMName + "\")" )
			
			BPB_BytsPerSec = ""
			byte = f.read(2)
			for b in byte:
				BPB_BytsPerSec += hex(ord(b)) + ","
			print( "\tBPB_BytsPerSec:\t" + BPB_BytsPerSec[:-1] )

			BPB_SecPerClus = ""
			byte = f.read(1)
			for b in byte:
				BPB_SecPerClus += hex(ord(b)) + ","
			print( "\tBPB_SecPerClus:\t" + BPB_SecPerClus[:-1] )

			BPB_RsvdSecCnt = ""
			byte = f.read(2)
			for b in byte:
				BPB_RsvdSecCnt += hex(ord(b)) + ","			
			print( "\tBPB_RsvdSecCnt:\t" + BPB_RsvdSecCnt[:-1] )

			BPB_NumFATs = ""
			byte = f.read(1)
			for b in byte:
				BPB_NumFATs += hex(ord(b)) + ","
			print( "\tBPB_NumFATs:\t" + BPB_NumFATs[:-1] )

			BPB_RootEntCnt = ""
			byte = f.read(2)
			for b in byte:
				BPB_RootEntCnt += hex(ord(b)) + ","
			print( "\tBPB_RootEntCnt:\t" + BPB_RootEntCnt[:-1] )
			
			BPB_TotSec16 = ""
			byte = f.read(2)
			for b in byte:
				BPB_TotSec16 += hex(ord(b)) + ","			
			print( "\tBPB_TotSec16:\t" + BPB_TotSec16[:-1] )

			BPB_Media = ""
			byte = f.read(1)
			for b in byte:
				BPB_Media += hex(ord(b)) + ","
			print( "\tBPB_Media:\t" + BPB_Media[:-1] )		

			BPB_FATSz16 = ""
			byte = f.read(2)
			for b in byte:
				BPB_FATSz16 += hex(ord(b)) + ","
			print( "\tBPB_FATSz16:\t" + BPB_FATSz16[:-1] )		
			
			BPB_SecPerTrk = ""
			byte = f.read(2)
			for b in byte:
				BPB_SecPerTrk += hex(ord(b)) + ","
			print( "\tBPB_SecPerTrk:\t" + BPB_SecPerTrk[:-1] )

			BPB_NumHeads = ""
			byte = f.read(2)
			for b in byte:
				BPB_NumHeads += hex(ord(b)) + ","
			print( "\tBPB_NumHeads:\t" + BPB_NumHeads[:-1] )

			BPB_HiddSec = ""
			byte = f.read(4)
			for b in byte:
				BPB_HiddSec += hex(ord(b)) + ","
			print( "\tBPB_HiddSec:\t" + BPB_HiddSec[:-1] )

			BPB_TotSec32 = ""
			byte = f.read(4)
			for b in byte:
				BPB_TotSec32 += hex(ord(b)) + ","
			print( "\tBPB_TotSec32:\t" + BPB_TotSec32[:-1] )

			print( "----- The next information is exclusive for FAT32 -----" )

			BPB_FATSz32 = ""
			byte = f.read(4)
			for b in byte:
				BPB_FATSz32 += hex(ord(b)) + ","
			print( "\tBPB_FATSz32:\t" + BPB_FATSz32[:-1] )		

			BPB_ExtFlags = ""
			byte = f.read(2)
			for b in byte:
				BPB_ExtFlags += hex(ord(b)) + ","
			print( "\tBPB_ExtFlags:\t" + BPB_ExtFlags[:-1] )		

			BPB_FSVer = ""
			byte = f.read(2)
			for b in byte:
				BPB_FSVer += hex(ord(b)) + ","
			print( "\tBPB_FSVer:\t" + BPB_FSVer[:-1] )		

			BPB_RootClus = ""
			byte = f.read(4)
			for b in byte:
				BPB_RootClus += hex(ord(b)) + ","
			print( "\tBPB_RootClus:\t" + BPB_RootClus[:-1] )		

			BPB_FSInfo = ""
			byte = f.read(2)
			for b in byte:
				BPB_FSInfo += hex(ord(b)) + ","
			print( "\tBPB_FSInfo:\t" + BPB_FSInfo[:-1] )

			BPB_BkBootSec = ""
			byte = f.read(2)
			for b in byte:
				BPB_BkBootSec += hex(ord(b)) + ","
			print( "\tBPB_BkBootSec:\t" + BPB_BkBootSec[:-1] )

			BPB_Reserved = ""
			byte = f.read(12)
			for b in byte:
				BPB_Reserved += hex(ord(b)) + ","
			print( "\tBPB_Reserved:\t" + BPB_Reserved[:-1] )

			BS_DrvNum = ""
			sBS_DrvNum = ""
			byte = f.read(1)
			for b in byte:
				BS_DrvNum += hex(ord(b)) + ","
			if ord(b) == 0x80:
				sBS_DrvNum = "Hard Disk"
			elif ord(b) == 0x00:
				sBS_DrvNum = "Floppy Disk"
			print( "\tBS_DrvNum:\t" + BS_DrvNum[:-1] + " Disk Type: " + sBS_DrvNum)

			BS_Reserved1 = ""
			byte = f.read(1)
			for b in byte:
				BS_Reserved1 += hex(ord(b)) + ","
			print( "\tBS_Reserved1:\t" + BS_Reserved1[:-1] )

			BS_BootSig = ""
			bBS_BootSig = False
			byte = f.read(1)
			for b in byte:
				BS_BootSig += hex(ord(b)) + ","
			if ord(b) == 0x29:
				bBS_BootSig = True
			print( "\tBS_BootSig:\t" + BS_BootSig[:-1] + " Extended boot signature: " + str(bBS_BootSig))

			BS_VolID = ""
			byte = f.read(4)
			for b in byte:
				BS_VolID += hex(ord(b)) + ","
			print( "\tBS_VolID:\t" + BS_VolID[:-1] )

			BS_VolLab = ""
			sBS_VolLab = ""
			byte = f.read(11)
			for b in byte:
				BS_VolLab += hex(ord(b)) + ","
				sBS_VolLab += b
			print( "\tBS_VolLab:\t" + BS_VolLab[:-1] + " (\"" + sBS_VolLab + "\")")

			BS_FilSysType = ""
			sBS_FilSysType = ""
			byte = f.read(8)
			for b in byte:
				BS_FilSysType += hex(ord(b)) + ","
				sBS_FilSysType += b
			print( "\tBS_FilSysType:\t" + BS_FilSysType[:-1] + " (\"" + sBS_FilSysType + "\")")


			"""
			while byte != "":
				
				# Do stuff with byte.
				byte = f.read(1)
			"""

		finally:
			f.close()

	else:
		print("The file doesn't exist.")
		sys.exit(2)

main()
