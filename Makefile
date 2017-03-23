SOURCES := $(shell ls *.cpp)

ssdp-bridge: $(SOURCES:%.cpp=%.o)
	@echo "[linking  ] $@"
	@g++ -flto -static -O3 -Wl,--strip-all -o $@ $^

%.o: %.cpp
	@echo "[compiling] $^"
	@g++ -flto -O3 -c -Wall -Wextra -Werror -Wfatal-errors -pedantic -std=c++14 -o $@ $^

clean:
	@echo "[cleaning ]"
	@rm -f *.o
