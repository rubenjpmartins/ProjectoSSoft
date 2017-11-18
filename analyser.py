#!/usr/bin/python
import sys
import json

#patterns File
PatternsFile = "patterns.txt"

#patterns List
Patterns = []

VulnerableVariables = {}

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

def checkPattern(children, pattern, VulnerableVariables):
	for i in xrange(0,len(children)):
		VulnerableVariables = checkVulnerableVariable(children[i], pattern, VulnerableVariables)

		print VulnerableVariables

def checkVulnerableVariable(line, pattern, VulnerableVariables):

	if line["kind"] == "assign":

		if line["right"]["kind"] == "offsetlookup":
			if line["right"]["what"]["name"] in pattern["entry_points"]:
					VulnerableVariables[line["left"]["name"]] = line["right"]["what"]["name"]

		elif line["right"]["kind"] == "encapsed":
			for j in line["right"]["value"]:
				if j["kind"] == "variable":
					if j["name"] in VulnerableVariables:
						VulnerableVariables[line["left"]["name"]] = VulnerableVariables[j["name"]]

		elif line["right"]["kind"] == "call":
			VulnerableVariables = checkArguments(line["left"]["name"], line["right"], pattern, VulnerableVariables)

	return VulnerableVariables

def checkArguments(possibleVuln, line, pattern, VulnerableVariables):
	if line["what"]["name"] not in pattern["sanitization"]:
		for i in line["arguments"]:
			if i["kind"] == "call":
				prevSize = len(VulnerableVariables)
				VulnerableVariables = checkArguments(possibleVuln, i, pattern, VulnerableVariables)
				if len(VulnerableVariables) > prevSize:
					return VulnerableVariables

			elif i["kind"] == "variable":
				if i["name"] in VulnerableVariables:
					VulnerableVariables[possibleVuln] = VulnerableVariables[i["name"]]
					return VulnerableVariables
	else:
		if possibleVuln in VulnerableVariables:
			VulnerableVariables.pop(possibleVuln)
	return VulnerableVariables


def analyzer(ast):
	children = ast["children"]
	VulnerableVariables = {}
	for pattern in Patterns:
		checkPattern(children, pattern, VulnerableVariables)
		VulnerableVariables = {}

if __name__ == '__main__':
	#read patterns file with the PatternsFile
	getPatternsFile(PatternsFile)
	path = "proj-slices/"
	filename = path + sys.argv[1]
	f = open(filename,"r")
	ast = json.load(f)
	f.close()
	analyzer(ast)
