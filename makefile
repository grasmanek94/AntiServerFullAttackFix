GPP = g++
GCC = gcc

OUTFILE = "./AntiServerFullFix.so"
IMMEDIATE_DIRECTORY = "*.o"

INCLUDE_DIRECTORIES=-I./
PREPROCESSOR_DEFINITIONS=-DLINUX -DNDEBUG -DRELEASE -D_LINUX -DAntiServerFullFix_EXPORTS -DSAMPGDK_AMALGAMATION -DSAMPGDK_LINUX -DSAMPGDK_STATIC -D__LINUX__
OPTIMIZATION_FLAGS=-O3
COMPATIBILITY_FLAGS=-finput-charset=windows-1252 -fshort-wchar -mfpmath=sse -msse2 -m32 -std=c++11

AntiServerFullFix = -c $(INCLUDE_DIRECTORIES) $(PREPROCESSOR_DEFINITIONS) $(OPTIMIZATION_FLAGS) $(COMPATIBILITY_FLAGS)

all: AntiServerFullFix

clean:
	-rm -f *~ *.o *.so

AntiServerFullFix: clean
	$(GPP) $(AntiServerFullFix) ./amxplugin.cpp
	$(GCC) $(AntiServerFullFix) ./sampgdk.c
	$(GPP) $(AntiServerFullFix) ./AntiServerFullAttack.cxx

	$(GPP) -shared -fwhole-program -flto $(COMPATIBILITY_FLAGS) $(OPTIMIZATION_FLAGS) -o $(OUTFILE) $(IMMEDIATE_DIRECTORY)
