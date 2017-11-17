#!/usr/bin/python
import sys
import json


#patterns File
PatternsFile = "patterns.txt"

#patterns List
Patterns = []


# Receives a patterns file and puts the patterns in a data structure
def getPatternsFile(filename):


	patternsFile = open(filename,"r")
	fileLines = patternsFile.readlines() 


	#parameter counter
	i=0
	patternsDict = {}

	for line in fileLines:

		if line in ['\n']:
			i=0
			continue

		else:
			#GET vulnerabilities	
			if i==0:
				patternsDict["vulnerabilities"] = line
				
				i += 1
				
			#GET entry_points	
			if i==1:
				patternsDict["entry_points"] = tuple(line.rstrip().split(','))
				
				i += 1

			#GET sanitization
			if i==2:
				patternsDict["sanitization"] = tuple(line.rstrip().split(','))
			
				i += 1


			#GET sensitive_sinks
			if i==3:
			  	patternsDict["sensitive_sinks"] = tuple(line.rstrip().split(','))
			  	
			  	print patternsDict
				i += 1

		


		'''
		#removes blank line and resets parameter counter
		if line in ['\n']:
			i=0
			Patterns.append(patternsDict)
			patternsDict = {}
			continue
		

		#GET vulnerabilities	
		if i==0:
			patternsDict["vulnerabilities"] = line
			print i
			i += 1
			

		#GET entry_points	
		if i==1:
			patternsDict["entry_points"] = tuple(line.rstrip().split(','))
			print i
			i += 1

		#GET sanitization
		if i==2:
			patternsDict["sanitization"] = tuple(line.rstrip().split(','))
			print i
			i += 1


		#GET sensitive_sinks
		if i==3:
		  	patternsDict["sensitive_sinks"] = tuple(line.rstrip().split(','))
		  	print i
		  	print patternsDict
			i += 1

		'''

	patternsFile.close()

	print Patterns








	







def analyzer(filename):
	f = open(filename,"r")
	contents = f.read()
	f.close()
	print contents 

if __name__ == '__main__':

	#read patterns file with the PatternsFile
	getPatternsFile(PatternsFile)

'''
	path = "proj-slices/"
	filename = path + sys.argv[1]
	analyzer(filename)
'''

