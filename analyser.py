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

	i=0
	patternsDict = {}

	for line in fileLines:

		line = line.replace('\n','')

		#if the line is empty
		if not line.strip():
			
			Patterns.append(patternsDict)
			patternsDict = {}
			i=0


		else:
			if i==0:
				patternsDict["vulnerabilities"] = line
				i = i + 1
				
			#GET entry_points
			elif i==1:
				patternsDict["entry_points"] = tuple(line.rstrip().translate(None, '$').split(','))
				i = i + 1

			#GET sanitization
			elif i==2:
				patternsDict["sanitization"] = tuple(line.rstrip().split(','))
				i = i + 1


			#GET sensitive_sinks
			else:
			  	patternsDict["sensitive_sinks"] = tuple(line.rstrip().split(','))
				i = i + 1

			
	return Patterns
		



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

