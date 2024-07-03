WIBO_CPP := $(notdir $(wildcard *.cpp))
WIBO_OBJS := $(WIBO_CPP:.cpp=.o)

MWCCEPPC_SECTIONS := text exc rdata data CRT idata bss
MWCCEPPC_SECTION_BINS := $(addprefix mwcceppc-, $(addsuffix .bin, $(MWCCEPPC_SECTIONS)))

.PHONY: all clean verify

all: mwcceppc verify

clean:
	rm -f mwcceppc *.o mwcceppc-*.bin *-labeled.s mwcceppc-sections.ld rsrc-string-table.c

rsrc-string-table.c: mwcceppc.exe
	./extract-rsrc-strings.py $< $@

mwcceppc-%.bin: mwcceppc.exe
	objcopy -O binary --only-section=.$* $< $@

mwcceppc-labeled.s: mwcceppc.exe $(MWCCEPPC_SECTION_BINS)
	./label-mwcceppc.py $< $@

mwcceppc-sections.ld: mwcceppc.exe
	./find-sections.py $< $@

%.o: %.s
	as --32 -o $@ $<

user32.o: user32.cpp rsrc-string-table.c

%.o: %.cpp
	g++ -m32 -O2 -Wall -c -o $@ $< -I.

mwcceppc: $(WIBO_OBJS) mwcceppc-labeled.o linkerscript.ld mwcceppc-sections.ld
	g++ -m32 -o $@ $(WIBO_OBJS) mwcceppc-labeled.o -T linkerscript.ld

verify: mwcceppc $(MWCCEPPC_SECTION_BINS)
	objcopy -O binary --only-section=.text mwcceppc mwcceppc-text-verify.bin
	cmp mwcceppc-text.bin mwcceppc-text-verify.bin

	objcopy -O binary --only-section=.exc mwcceppc mwcceppc-exc-verify.bin
	cmp mwcceppc-exc.bin mwcceppc-exc-verify.bin

	objcopy -O binary --only-section=.rdata mwcceppc mwcceppc-rdata-verify.bin
	cmp mwcceppc-rdata.bin mwcceppc-rdata-verify.bin

	objcopy -O binary --only-section=.data mwcceppc mwcceppc-data-verify.bin
	cmp mwcceppc-data.bin mwcceppc-data-verify.bin

	objcopy -O binary --only-section=.crt mwcceppc mwcceppc-crt-verify.bin
	cmp mwcceppc-CRT.bin mwcceppc-crt-verify.bin
