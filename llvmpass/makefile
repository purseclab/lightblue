
.PHONE=all clean

# The name of the plugin.
SRC = $(wildcard *.cpp)
OBJ = $(SRC:.cpp=.o)
LIB_OUT = BTanalysis

# LLVM paths. Note: you probably need to update these.
LLVM_DIR = /home/wu/tools-bin/llvm-tools

# Compiler flags.
CXXFLAGS  = -I$(LLVM_DIR)/include -I.
CXXFLAGS += -D__STDC_LIMIT_MACROS -D__STDC_CONSTANT_MACROS -Wno-long-long
CXXFLAGS += -fPIC -fvisibility-inlines-hidden
CXXFLAGS += -fno-exceptions -fno-rtti -std=c++11
CXXFLAGS += -Wall -g

# Linker flags.
LDFLAGS = -shared -Wl,-undefined,dynamic_lookup

all : $(LIB_OUT).so

$(LIB_OUT).so : $(OBJ)
	@clang++ $(LDFLAGS) -o $(LIB_OUT).so $(OBJ)

%.o : %.cpp
	@clang++ $(CXXFLAGS) -c -o $@ $<

clean :
	@rm -fv $(LIB_OUT).so $(OBJ)
