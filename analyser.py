#!/usr/bin/python
import sys


def analyzer(filename):
	f = open(filename,"r")
	contents = f.read()
	f.close()
	print contents 

if __name__ == '__main__':
	path = "proj-slices/"
	filename = path + sys.argv[1]
	analyzer(filename)
