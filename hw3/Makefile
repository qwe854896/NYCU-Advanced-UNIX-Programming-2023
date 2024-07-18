CXX = g++
EXEC = sdb
LDFLAGS = -lcapstone

all: $(EXEC)

clean:
	rm -f $(EXEC)

$(EXEC): sdb.cpp
	$(CXX) -o $@ $^ $(LDFLAGS)
