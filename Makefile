CXX = g++
CXXFLAGS = -Wall -g -std=gnu++14

all : pedump
pedump : pedump.cpp

clean :
	-rm -f pedump
