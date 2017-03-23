SOURCES := $(shell ls *.cpp)

ssdp-bridge: $(SOURCES:%.cpp=%.o)
	@echo "[linking  ] $@"
	@g++ -flto -O3 -o $@ $^

%.o: %.cpp
	@echo "[compiling] $^"
	@g++ -flto -O3 -c -Wall -Wextra -Werror -pedantic -std=c++14 -o $@ $^

clean:
	@echo "[cleaning ]"
	@rm -f *.o
