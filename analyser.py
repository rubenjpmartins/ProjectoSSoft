#!/usr/bin/python
import sys
import json
import copy

#patterns File
PatternsFile = "patterns.txt"

#patterns List
Patterns = []

VariableRelations = {}

sanitizationUsed = ""

def getPatternsFile(filename):

	patternsFile = open(filename,"r")
	fileLines = patternsFile.readlines() 
	lastLine = fileLines[-1]

	i=0
	patternsDict = {}

	for line in fileLines:
		line = line.replace('\n','')

		#if the line is empty
		if not line.strip():
			Patterns.append(patternsDict)
			patternsDict = {}
			i=0

		#if last line
		elif line is lastLine:
			patternsDict["sensitive_sinks"] = tuple(line.rstrip().split(','))
			Patterns.append(patternsDict)
			patternsDict = {}
			i=0

		else:
			#GET vulnerabilities
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
		#print VariableRelations

def checkVulnerableVariable(line, pattern, VulnerableVariables):

	VulnerableVariables = checkIfStatements(1, line, pattern, VulnerableVariables, {}, {})

	VulnerableVariables = checkWhileCondition(line, pattern, VulnerableVariables)

	if line["kind"] == "assign":

		if line["right"]["kind"] == "offsetlookup":
			if line["right"]["what"]["name"] in pattern["entry_points"]:
					VulnerableVariables[line["left"]["name"]] = line["right"]["what"]["name"]
					checkVulnVarInfluencesOthers(line["left"]["name"], VulnerableVariables)

		elif line["right"]["kind"] == "encapsed":
			for j in line["right"]["value"]:
				if j["kind"] == "variable":
					VariableRelations.setdefault(line["left"]["name"], [])
					VariableRelations[line["left"]["name"]].append(j["name"])
					if j["name"] in VulnerableVariables:
						VulnerableVariables[line["left"]["name"]] = j["name"]
						checkVulnVarInfluencesOthers(line["left"]["name"], VulnerableVariables)

		elif line["right"]["kind"] == "call":
			VulnerableVariables = checkArguments(line["left"]["name"], line["right"], pattern, VulnerableVariables)

		elif line["right"]["kind"] == "variable":
			VariableRelations.setdefault(line["left"]["name"], [])
			VariableRelations[line["left"]["name"]].append(line["right"]["name"])
			if line["right"]["name"] in VulnerableVariables:
				VulnerableVariables[line["left"]["name"]] = line["right"]["name"]
				checkVulnVarInfluencesOthers(line["left"]["name"], VulnerableVariables)

		elif line["right"]["kind"] == "bin":

			VariableRelations.setdefault(line["left"]["name"], [])
			VariableRelations[line["left"]["name"]].append(line["right"]["left"]["name"])
			VariableRelations[line["left"]["name"]].append(line["right"]["right"]["name"])
			if line["right"]["left"]["name"] in VulnerableVariables:
				VulnerableVariables[line["left"]["name"]] = line["right"]["left"]["name"]
				checkVulnVarInfluencesOthers(line["left"]["name"], VulnerableVariables)
			elif line["right"]["right"]["name"] in VulnerableVariables:
				VulnerableVariables[line["left"]["name"]] = line["right"]["right"]["name"]
				checkVulnVarInfluencesOthers(line["left"]["name"], VulnerableVariables)

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
				VariableRelations.setdefault(possibleVuln, [])
				VariableRelations[possibleVuln].append(i["name"])
				if i["name"] in VulnerableVariables:
					VulnerableVariables[possibleVuln] = i["name"]
					checkVulnVarInfluencesOthers(possibleVuln, VulnerableVariables)
					return VulnerableVariables
	else:
		sanitizationUsed = line["what"]["name"]
		if possibleVuln in VulnerableVariables:
			VulnerableVariables.pop(possibleVuln)
		for i in line["arguments"]:
			if i["kind"] == "variable":
				VariableRelations.setdefault(possibleVuln, [])
				VariableRelations[possibleVuln].append(i["name"])
	return VulnerableVariables

def checkVulnVarInfluencesOthers(vulnVariable, VulnerableVariables):
	for key, value in VariableRelations.items():
		for i in value:
			if i == vulnVariable:
				if key not in VulnerableVariables:
					VulnerableVariables[key] = vulnVariable
					checkVulnVarInfluencesOthers(key, VulnerableVariables)


def checkWhileCondition(line, pattern, VulnerableVariables):
	if line["kind"] == "while":
		copyVulnerableVariables = copy.deepcopy(VulnerableVariables)
		for i in xrange(0,len(line["body"]["children"])):
			copyVulnerableVariables = checkVulnerableVariable(line["body"]["children"][i], pattern, copyVulnerableVariables)
		newElements = getNewIfNewElementInCopy(VulnerableVariables, copyVulnerableVariables, {})
		for key, value in newElements.items():
				VulnerableVariables[key] = value
				checkVulnVarInfluencesOthers(key, VulnerableVariables)
	return VulnerableVariables

def checkIfStatements(caseNumber, line, pattern, VulnerableVariables, newElements, sanitizationElements):
	if line["kind"] == "if":
		copyVulnerableVariables = copy.deepcopy(VulnerableVariables)
		for i in xrange(0,len(line["body"]["children"])):
			copyVulnerableVariables = checkVulnerableVariable(line["body"]["children"][i], pattern, copyVulnerableVariables)
		sanitizationElements = getRemovedIfRemovedElementFromCopy(VulnerableVariables, copyVulnerableVariables, sanitizationElements)
		newElements = getNewIfNewElementInCopy(VulnerableVariables, copyVulnerableVariables, newElements)
		if line["alternate"] != None:
			if line["alternate"]["kind"] == "block":
				copyVulnerableVariables = copy.deepcopy(VulnerableVariables)
				for i in xrange(0,len(line["alternate"]["children"])):
					copyVulnerableVariables = checkVulnerableVariable(line["alternate"]["children"][i], pattern, copyVulnerableVariables)
				sanitizationElements = getRemovedIfRemovedElementFromCopy(VulnerableVariables, copyVulnerableVariables, sanitizationElements)
				for i in sanitizationElements:
					if sanitizationElements[i] == caseNumber + 1:
						if i in VulnerableVariables:
							VulnerableVariables.pop(i)
				newElements = getNewIfNewElementInCopy(VulnerableVariables, copyVulnerableVariables, newElements)
			elif line["alternate"]["kind"] == "if":
				VulnerableVariables = checkIfStatements(caseNumber+1, line["alternate"], pattern, VulnerableVariables, newElements, sanitizationElements, VariableRelations)
		if caseNumber == 1:
			for key, value in newElements.items():
				VulnerableVariables[key] = value
				checkVulnVarInfluencesOthers(key, VulnerableVariables)
	return VulnerableVariables

def getRemovedIfRemovedElementFromCopy(originalVulnDict, copyVulnDict, returnSanitizationElements):
	sanitizationElements = {}
	for key, value in originalVulnDict.items():
		if key not in copyVulnDict:
			sanitizationElements[key] = value
	for key, value in sanitizationElements.items():
		if key not in returnSanitizationElements:
			returnSanitizationElements[key] = 1
		else:
			returnSanitizationElements[key] += 1
	return returnSanitizationElements

def getNewIfNewElementInCopy(originalVulnDict, copyVulnDict, returnNewElementsDict):
	newElements = {}
	for key, value in copyVulnDict.items():
		if key not in originalVulnDict:
			newElements[key] = value
	for key, value in newElements.items():
		if key not in returnNewElementsDict:
			returnNewElementsDict[key] = value
	return returnNewElementsDict

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
	global VariableRelations
	global sanitizationUsed
	for pattern in Patterns:
		checkPattern(children, pattern, VulnerableVariables)
		VulnerableVariables = {}
		VariableRelations = {}

if __name__ == '__main__':
	#read patterns file with the PatternsFile
	getPatternsFile(PatternsFile)
	path = "proj-slices/"
	filename = path + sys.argv[1]
	f = open(filename,"r")
	ast = json.load(f)
	f.close()
	analyzer(ast)
