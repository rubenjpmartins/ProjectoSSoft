import os

print "SLICE1:"
os.system("python ./analyser.py slice1.json")
for i in xrange(1,3):
	print "SLICE1." + str(i) + ":"
	os.system("python ./analyser.py slice1." + str(i) + ".json")

print "SLICE2:"
os.system("python ./analyser.py slice2.json")
for i in xrange(1,2):
	print "SLICE2." + str(i) + ":"
	os.system("python ./analyser.py slice2." + str(i) + ".json")

print "SLICE3:"
os.system("python ./analyser.py slice3.json")
for i in xrange(1,2):
	print "SLICE3." + str(i) + ":"
	os.system("python ./analyser.py slice3." + str(i) + ".json")

print "SLICE4:"
os.system("python ./analyser.py slice4.json")
for i in xrange(1,2):
	print "SLICE4." + str(i) + ":"
	os.system("python ./analyser.py slice4." + str(i) + ".json")

print "SLICE5:"
os.system("python ./analyser.py slice5.json")
for i in xrange(1,5):
	print "SLICE5." + str(i) + ":"
	os.system("python ./analyser.py slice5." + str(i) + ".json")

print "SLICE6:"
os.system("python ./analyser.py slice6.json")
for i in xrange(1,2):
	print "SLICE6." + str(i) + ":"
	os.system("python ./analyser.py slice6." + str(i) + ".json")

print "SLICE7:"
os.system("python ./analyser.py slice7.json")
for i in xrange(1,4):
	print "SLICE7." + str(i) + ":"
	os.system("python ./analyser.py slice7." + str(i) + ".json")

print "SLICE8:"
os.system("python ./analyser.py slice8.json")
for i in xrange(1,7):
	print "SLICE8." + str(i) + ":"
	os.system("python ./analyser.py slice8." + str(i) + ".json")

print "SLICE9:"
os.system("python ./analyser.py slice9.json")
for i in xrange(1,6):
	print "SLICE9." + str(i) + ":"
	os.system("python ./analyser.py slice9." + str(i) + ".json")

print "SLICE10:"
os.system("python ./analyser.py slice10.json")
for i in xrange(1,7):
	print "SLICE10." + str(i) + ":"
	os.system("python ./analyser.py slice10." + str(i) + ".json")

print "SLICE11:"
os.system("python ./analyser.py slice11.json")
for i in xrange(1,1):
	print "SLICE11." + str(i) + ":"
	os.system("python ./analyser.py slice11." + str(i) + ".json")
