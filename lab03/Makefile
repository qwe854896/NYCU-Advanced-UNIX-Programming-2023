all: libsolver.so

libsolver.so: libsolver.o
	$(CC) -shared -o $@ $^

libsolver.o: libsolver.c
	$(CC) -fPIC -c -o $@ $^

clean:
	rm -rf libsolver.o libsolver.so
