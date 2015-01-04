GPP = c++
GCC = cc

OUTFILE = "./AntiServerFullFix.so"

INCLUDE_DIRECTORIES=-I./
PREPROCESSOR_DEFINITIONS=-DLINUX -DNDEBUG -DRELEASE -D_LINUX -DAntiServerFullFix_EXPORTS -DSAMPGDK_AMALGAMATION -DSAMPGDK_LINUX -DSAMPGDK_STATIC -D__LINUX__
OPTIMIZATION_FLAGS=-O3
COMPATIBILITY_FLAGS=-finput-charset=windows-1252 -fshort-wchar -mfpmath=sse -msse2 -m32 -std=c++11

AntiServerFullFix = -c $(INCLUDE_DIRECTORIES) $(PREPROCESSOR_DEFINITIONS) $(OPTIMIZATION_FLAGS) $(COMPATIBILITY_FLAGS)
SAMP_GDK = -c $(INCLUDE_DIRECTORIES) $(PREPROCESSOR_DEFINITIONS) $(OPTIMIZATION_FLAGS) -m32

all: AntiServerFullFix

clean:
	-rm -f *~ *.o *.so

AntiServerFullFix: clean
	$(GPP) $(AntiServerFullFix) ./amxplugin.cpp
	$(GCC) $(SAMP_GDK) ./sampgdk.c
	$(GPP) $(AntiServerFullFix) ./AntiServerFullAttack.cxx

	$(GPP) -shared -m32 -lrt -o $(OUTFILE) *.o
