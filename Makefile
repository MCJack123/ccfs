CC=gcc
CXX=g++
CFLAGS=-g -O2
CXXFLAGS=-std=c++14
LDFLAGS=
LIBS=-lfuse3 -lPocoNet -lPocoNetSSL -lPocoFoundation -lPocoUtil

ccfs: ccfs.o connection.o
	$(CXX) -o $@ $^ $(LDFLAGS) $(LIBS)

ccfs.o: ccfs.c connection.h
	$(CC) $(CFLAGS) -c -o $@ $<

connection.o: connection.cpp connection.h
	$(CXX) $(CFLAGS) $(CXXFLAGS) -c -o $@ $<

clean:
	rm ccfs