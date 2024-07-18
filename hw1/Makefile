CC = g++

all: logger logger.so

logger.so: logger.o
	$(CC) -shared -o $@ $^

logger.o: logger.cpp
	$(CC) -fPIC -c -o $@ $^

logger: logger.o
	$(CC) -o $@ $^ -L. -Wl,-rpath .

clean:
	rm -f *.o *.so logger file.txt *.log

.PHONY: all clean

