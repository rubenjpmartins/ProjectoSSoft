import os

NumberSlice = 11

count = 1

while count < NumberSlice + 1:
	print "SLICE " + str(count) + ":"
	os.system("python ./analyser.py proj-slices/slice" + str(count) + ".json")
	count = count + 1 
	