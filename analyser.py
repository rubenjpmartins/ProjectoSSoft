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
		checkSensitiveSink(children[i], pattern, VulnerableVariables)

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
						VulnerableVariables[line["left"]["name"]] = j["name"]

		elif line["right"]["kind"] == "call":
			VulnerableVariables = checkArguments(line["left"]["name"], line["right"], pattern, VulnerableVariables)

		elif line["right"]["kind"] == "variable":
			if line["right"]["name"] in VulnerableVariables:
				VulnerableVariables[line["left"]["name"]] = line["right"]["name"]

		elif line["right"]["kind"] == "bin":
			if line["right"]["left"]["name"] in VulnerableVariables:
				VulnerableVariables[line["left"]["name"]] = line["right"]["left"]["name"]
			elif line["right"]["right"]["name"] in VulnerableVariables:
				VulnerableVariables[line["left"]["name"]] = line["right"]["right"]["name"]			

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
					VulnerableVariables[possibleVuln] = i["name"]
					return VulnerableVariables
	else:
		if possibleVuln in VulnerableVariables:
			if VulnerableVariables[possibleVuln] in pattern["entry_points"]:
				VulnerableVariables.pop(possibleVuln)
	return VulnerableVariables

def checkSensitiveSink(line, pattern, VulnerableVariables):
	if line["kind"] == "assign":
		if line["right"]["kind"] == "call":
			if line["right"]["what"]["name"] in pattern["sensitive_sinks"]:
				checkSensitiveSinkHasVulnerability(True, line["right"]["arguments"], pattern, VulnerableVariables)
			else:
				checkSensitiveSinkHasVulnerability(False, line["right"]["arguments"], pattern, VulnerableVariables)
	elif line["kind"] == "call":
		if line["what"]["name"] in pattern["sensitive_sinks"]:
			checkSensitiveSinkHasVulnerability(True, line["arguments"], pattern, VulnerableVariables)
		else:
			checkSensitiveSinkHasVulnerability(False, line["arguments"], pattern, VulnerableVariables)
	elif line["kind"] in pattern["sensitive_sinks"]:
		checkSensitiveSinkHasVulnerability(True, line["arguments"], pattern, VulnerableVariables)
		

def checkSensitiveSinkHasVulnerability(passedInSensitiveSink, line, pattern, VulnerableVariables):
	if passedInSensitiveSink == True:
		for i in line:
			if i["kind"] == "variable":
				if i["name"] in VulnerableVariables:
					print "Has vulnerability, should use the function " + pattern["sanitization"][0] + " for sanitization"
			elif i["kind"] == "offsetlookup":
				if i["what"]["name"] in pattern["entry_points"]:
					print "Has vulnerability, should use the function " + pattern["sanitization"][0] + " for sanitization"
			elif i["kind"] == "call":
				if i["what"]["name"] in pattern["sensitive_sinks"]:
					checkSensitiveSinkHasVulnerability(True, i["arguments"], pattern, VulnerableVariables)
				else:
					checkSensitiveSinkHasVulnerability(False, i["arguments"], pattern, VulnerableVariables)
	elif passedInSensitiveSink == False:
		for i in line:
			if i["kind"] == "call":
				if i["what"]["name"] in pattern["sensitive_sinks"]:
					checkSensitiveSinkHasVulnerability(True, i["arguments"], pattern, VulnerableVariables)
				else:
					checkSensitiveSinkHasVulnerability(False, i["arguments"], pattern, VulnerableVariables)

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
