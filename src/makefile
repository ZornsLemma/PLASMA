.SUFFIXES	=
AFLAGS	= -o $@
PLVM    = plvm
PLVM01  = A1PLASMA\#060280
PLVM02	= PLASMA.SYSTEM\#FF2000
PLVM03	= SOS.INTERP\#050000
PLVM32  = BBPLASMA\#FF2000
PLVM32X = BBPLASMA\#FF3000
PLVM128 = BBPLAS128\#FF2000
PLVM128X= BBPLAS128\#FF3000
CMD     = CMD\#FF2000
ED      = ED\#FF2000
SB      = SB\#FF2000
ROD     = ROD\#FE1000
SIEVE   = SIEVE\#FE1000
ARGS    = ARGS\#FE1000
SPIPORT = SPIPORT\#FE1000
SDFAT   = SDFAT\#FE1000
FATCAT  = FATCAT\#FE1000
FATGET  = FATGET\#FE1000
FATPUT  = FATPUT\#FE1000
FATWDSK = FATWRITEDSK\#FE1000
FATRDSK = FATREADDSK\#FE1000
FILEIO  = FILEIO\#FE1000
WIZNET  = WIZNET\#FE1000
UTHERNET2= UTHERNET2\#FE1000
UTHERNET= UTHERNET\#FE1000
ETHERIP = ETHERIP\#FE1000
INET    = INET\#FE1000
DHCP    = DHCP\#FE1000
HTTPD   = HTTPD\#FE1000
DGR     = DGR\#FE1000
TONE    = TONE\#FE1000
PORTIO  = PORTIO\#FE1000
ROGUE   = ROGUE\#FE1000
ROGUEIO = ROGUEIO\#FE1000
ROGUEMAP= ROGUEMAP\#FE1000
ROGUECOMBAT= ROGUECOMBAT\#FE1000
HELLO   = HELLO\#FE1000
MON     = MON\#FE1000
HGR1    = HGR1\#FE1000
HGR1TEST= HGR1TEST\#FE1000
DGRTEST = DGRTEST\#FE1000
TEST    = TEST\#FE1000
TESTLIB = TESTLIB\#FE1000
PROFILE = PROFILE\#FE1000
MEMMGR  = MEMMGR\#FE1000
MEMTEST = MEMTEST\#FE1000
FIBER   = FIBER\#FE1000
ACORNOS = ACORNOS\#FE1000
BBSSD   = plasma.ssd
PLASM   = plasm
INCS    = toolsrc/tokens.h toolsrc/symbols.h toolsrc/lex.h toolsrc/parse.h toolsrc/codegen.h
OBJS	= toolsrc/plasm.c toolsrc/parse.o toolsrc/lex.o toolsrc/codegen.o
#
# Image filetypes for Virtual ][
#
PLATYPE	= .\$$ED
BINTYPE	= .BIN
SYSTYPE	= .SYS
TXTTYPE	= .TXT
#
# Image filetypes for CiderPress
#
#RELTYPE	= \#FE1000
#INTERPTYPE	= \#050000
#BINTYPE	= \#060000
#SYSTYPE	= \#FF2000
#TXTTYPE	= \#040000

all: $(PLASM) $(PLVM) $(PLVM01) $(PLVM02) $(PLVM03) $(PLVM32) $(PLVM128) $(CMD) $(ARGS) $(MEMMGR) $(MEMTEST) $(FIBER) $(SB) $(MON) $(ROD) $(SIEVE) $(UTHERNET2) $(UTHERNET) $(ETHERIP) $(INET) $(DHCP) $(HTTPD) $(ROGUE) $(ROGUEMAP) $(ROGUECOMBAT) $(ROGUEIO) $(HGR1) $(TONE) $(DGR) $(DGRTEST) $(FILEIO) $(PORTIO) $(SPIPORT) $(SDFAT) $(FATCAT) $(FATGET) $(FATPUT) $(FATWDSK) $(FATRDSK) $(BBSSD)

clean:
	-rm *FE1000 *FF2000 *FF3000 $(PLASM) $(PLVM) $(PLVM01) $(PLVM02) $(PLVM03) $(PLVM32) $(PLVM128)
	-rm toolsrc/*.o toolsrc/*~ toolsrc/*.a
	-rm vmsrc/*.o vmsrc/*~ vmsrc/*.a vmsrc/*.sym vmsrc/32cmd.* vmsrc/128cmd.*
	-rm samplesrc/*.o samplesrc/*~ samplesrc/*.a
	-rm plasma.ssd

#
# PLASMA compiler: plasm
#
$(PLASM): $(OBJS) $(INCS)
	cc $(OBJS) -o $(PLASM)

#
# PLASMA VMs
#
$(PLVM): vmsrc/plvm.c
	cc vmsrc/plvm.c -o $(PLVM)

vmsrc/a1cmd.a: vmsrc/a1cmd.pla $(PLASM)
	./$(PLASM) -A < vmsrc/a1cmd.pla > vmsrc/a1cmd.a

$(PLVM01): vmsrc/plvm01.s vmsrc/a1cmd.a
	acme -o $(PLVM01) -l vmsrc/plvm01.sym vmsrc/plvm01.s

vmsrc/32cmd.a: vmsrc/bbcmd.pla $(PLASM)
	cc -E -P - < vmsrc/bbcmd.pla > vmsrc/32cmd.pla
	./$(PLASM) -A < vmsrc/32cmd.pla > vmsrc/32cmd.a

vmsrc/128cmd.a: vmsrc/bbcmd.pla $(PLASM)
	cc -DPLAS128 -E -P - < vmsrc/bbcmd.pla > vmsrc/128cmd.pla
	./$(PLASM) -A < vmsrc/128cmd.pla > vmsrc/128cmd.a

$(PLVM32): vmsrc/plvmbb.s vmsrc/32cmd.a add-relocations.py
	acme '-DSTART=$$2000' -o $(PLVM32) -l vmsrc/plvm32.sym vmsrc/plvmbb.s
	acme '-DSTART=$$3000' -o $(PLVM32X) -l vmsrc/plvm32x.sym vmsrc/plvmbb.s
	python add-relocations.py $(PLVM32) $(PLVM32X)

$(PLVM128): vmsrc/plvmbb.s vmsrc/128cmd.a add-relocations.py
	acme '-DSTART=$$2000' -DPLAS128=1 -o $(PLVM128) -l vmsrc/plvm128.sym vmsrc/plvmbb.s
	acme '-DSTART=$$3000' -DPLAS128=1 -o $(PLVM128X) vmsrc/plvmbb.s
	python add-relocations.py $(PLVM128) $(PLVM128X)

$(CMD): vmsrc/cmd.pla vmsrc/cmdstub.s $(PLVM02) $(PLASM)
	./$(PLASM) -A < vmsrc/cmd.pla > vmsrc/cmd.a
	acme --setpc 8192 -o $(CMD) vmsrc/cmdstub.s

$(PLVM02): vmsrc/plvm02.s
	acme -o $(PLVM02) -l vmsrc/plvm02.sym vmsrc/plvm02.s

vmsrc/soscmd.a: vmsrc/soscmd.pla $(PLASM)
	./$(PLASM) -A < vmsrc/soscmd.pla > vmsrc/soscmd.a

$(PLVM03): vmsrc/plvm03.s vmsrc/soscmd.a
	acme -o $(PLVM03) -l vmsrc/plvm03.sym vmsrc/plvm03.s

#
# Sample code
#
testint:	samplesrc/test.pla samplesrc/testlib.pla $(PLVM) $(PLASM)
	./$(PLASM) -AM  < samplesrc/test.pla > samplesrc/test.a
	acme --setpc 4094 -o $(TEST) samplesrc/test.a
	./$(PLASM) -AM  < samplesrc/testlib.pla > samplesrc/testlib.a
	acme --setpc 4094 -o $(TESTLIB) samplesrc/testlib.a

test: testint
	./$(PLVM) TEST

$(ED): toolsrc/ed.pla $(PLVM02) $(PLASM) toolsrc/ed.pla
	./$(PLASM) -A < toolsrc/ed.pla > toolsrc/ed.a
	acme --setpc 8192 -o $(ED) toolsrc/ed.a

$(SB): toolsrc/sb.pla $(PLVM02) $(PLASM) toolsrc/sb.pla
	./$(PLASM) -A < toolsrc/sb.pla > toolsrc/sb.a
	acme --setpc 8192 -o $(SB) toolsrc/sb.a

$(ARGS): libsrc/args.pla $(PLVM02) $(PLASM)
	./$(PLASM) -AM < libsrc/args.pla > libsrc/args.a
	acme --setpc 4094 -o $(ARGS) libsrc/args.a

$(MEMMGR): libsrc/memmgr.pla $(PLVM02) $(PLASM)
	./$(PLASM) -AM < libsrc/memmgr.pla > libsrc/memmgr.a
	acme --setpc 4094 -o $(MEMMGR) libsrc/memmgr.a

$(MEMTEST): samplesrc/memtest.pla $(PLVM02) $(PLASM)
	./$(PLASM) -AM < samplesrc/memtest.pla > samplesrc/memtest.a
	acme --setpc 4094 -o $(MEMTEST) samplesrc/memtest.a

$(FIBER): libsrc/fiber.pla $(PLVM02) $(PLASM)
	./$(PLASM) -AM < libsrc/fiber.pla > libsrc/fiber.a
	acme --setpc 4094 -o $(FIBER) libsrc/fiber.a

$(MON): samplesrc/mon.pla $(PLVM02) $(PLASM)
	./$(PLASM) -AM < samplesrc/mon.pla > samplesrc/mon.a
	acme --setpc 4094 -o $(MON) samplesrc/mon.a

$(ROD): samplesrc/rod.pla $(PLVM02) $(PLASM)
	./$(PLASM) -AM < samplesrc/rod.pla > samplesrc/rod.a
	acme --setpc 4094 -o $(ROD) samplesrc/rod.a

$(SIEVE): samplesrc/sieve.pla $(PLVM02) $(PLASM)
	./$(PLASM) -AM < samplesrc/sieve.pla > samplesrc/sieve.a
	acme --setpc 4094 -o $(SIEVE) samplesrc/sieve.a

$(UTHERNET): libsrc/uthernet.pla $(PLVM02) $(PLASM)
	./$(PLASM) -AM < libsrc/uthernet.pla > libsrc/uthernet.a
	acme --setpc 4094 -o $(UTHERNET) libsrc/uthernet.a

$(UTHERNET2): libsrc/uthernet2.pla $(PLVM02) $(PLASM)
	./$(PLASM) -AM < libsrc/uthernet2.pla > libsrc/uthernet2.a
	acme --setpc 4094 -o $(UTHERNET2) libsrc/uthernet2.a

$(ETHERIP): libsrc/etherip.pla $(PLVM02) $(PLASM)
	./$(PLASM) -AM < libsrc/etherip.pla > libsrc/etherip.a
	acme --setpc 4094 -o $(ETHERIP) libsrc/etherip.a

$(INET): libsrc/inet.pla $(PLVM02) $(PLASM)
	./$(PLASM) -AM < libsrc/inet.pla > libsrc/inet.a
	acme --setpc 4094 -o $(INET) libsrc/inet.a

$(DHCP): libsrc/dhcp.pla $(PLVM02) $(PLASM)
	./$(PLASM) -AM < libsrc/dhcp.pla > libsrc/dhcp.a
	acme --setpc 4094 -o $(DHCP) libsrc/dhcp.a

$(HTTPD): samplesrc/httpd.pla $(PLVM02) $(PLASM)
	./$(PLASM) -AM < samplesrc/httpd.pla > samplesrc/httpd.a
	acme --setpc 4094 -o $(HTTPD) samplesrc/httpd.a

$(FILEIO): libsrc/fileio.pla $(PLVM02) $(PLASM)
	./$(PLASM) -AM < libsrc/fileio.pla > libsrc/fileio.a
	acme --setpc 4094 -o $(FILEIO) libsrc/fileio.a

$(TONE): libsrc/tone.pla $(PLVM02) $(PLASM)
	./$(PLASM) -AM < libsrc/tone.pla > libsrc/tone.a
	acme --setpc 4094 -o $(TONE) libsrc/tone.a

$(FATCAT): samplesrc/fatcat.pla $(PLVM02) $(PLASM)
	./$(PLASM) -AM < samplesrc/fatcat.pla > samplesrc/fatcat.a
	acme --setpc 4094 -o $(FATCAT) samplesrc/fatcat.a

$(FATGET): samplesrc/fatget.pla $(PLVM02) $(PLASM)
	./$(PLASM) -AM < samplesrc/fatget.pla > samplesrc/fatget.a
	acme --setpc 4094 -o $(FATGET) samplesrc/fatget.a

$(FATPUT): samplesrc/fatput.pla $(PLVM02) $(PLASM)
	./$(PLASM) -AM < samplesrc/fatput.pla > samplesrc/fatput.a
	acme --setpc 4094 -o $(FATPUT) samplesrc/fatput.a

$(FATWDSK): samplesrc/fatwritedsk.pla $(PLVM02) $(PLASM)
	./$(PLASM) -AM < samplesrc/fatwritedsk.pla > samplesrc/fatwritedsk.a
	acme --setpc 4094 -o $(FATWDSK) samplesrc/fatwritedsk.a

$(FATRDSK): samplesrc/fatreaddsk.pla $(PLVM02) $(PLASM)
	./$(PLASM) -AM < samplesrc/fatreaddsk.pla > samplesrc/fatreaddsk.a
	acme --setpc 4094 -o $(FATRDSK) samplesrc/fatreaddsk.a

$(SDFAT): libsrc/sdfat.pla $(PLVM02) $(PLASM)
	./$(PLASM) -AM < libsrc/sdfat.pla > libsrc/sdfat.a
	acme --setpc 4094 -o $(SDFAT) libsrc/sdfat.a

$(SPIPORT): libsrc/spiport.pla $(PLVM02) $(PLASM)
	./$(PLASM) -AM < libsrc/spiport.pla > libsrc/spiport.a
	acme --setpc 4094 -o $(SPIPORT) libsrc/spiport.a

$(PORTIO): libsrc/portio.pla $(PLVM02) $(PLASM)
	./$(PLASM) -AM < libsrc/portio.pla > libsrc/portio.a
	acme --setpc 4094 -o $(PORTIO) libsrc/portio.a

$(DGR): libsrc/dgr.pla $(PLVM02) $(PLASM)
	./$(PLASM) -AM < libsrc/dgr.pla > libsrc/dgr.a
	acme --setpc 4094 -o $(DGR) libsrc/dgr.a

$(DGRTEST): samplesrc/dgrtest.pla $(PLVM02) $(PLASM)
	./$(PLASM) -AM < samplesrc/dgrtest.pla > samplesrc/dgrtest.a
	acme --setpc 4094 -o $(DGRTEST) samplesrc/dgrtest.a

$(ROGUE): samplesrc/rogue.pla $(PLVM02) $(PLASM)
	./$(PLASM) -AM < samplesrc/rogue.pla > samplesrc/rogue.a
	acme --setpc 4094 -o $(ROGUE) samplesrc/rogue.a

$(ROGUEIO): samplesrc/rogue.io.pla $(PLVM02) $(PLASM)
	./$(PLASM) -AM < samplesrc/rogue.io.pla > samplesrc/rogue.io.a
	acme --setpc 4094 -o $(ROGUEIO) samplesrc/rogue.io.a

$(ROGUECOMBAT): samplesrc/rogue.combat.pla $(PLVM02) $(PLASM)
	./$(PLASM) -AM < samplesrc/rogue.combat.pla > samplesrc/rogue.combat.a
	acme --setpc 4094 -o $(ROGUECOMBAT) samplesrc/rogue.combat.a

$(ROGUEMAP): samplesrc/rogue.map.pla $(PLVM02) $(PLASM)
	./$(PLASM) -AM < samplesrc/rogue.map.pla > samplesrc/rogue.map.a
	acme --setpc 4094 -o $(ROGUEMAP) samplesrc/rogue.map.a

$(HGR1):	samplesrc/hgr1.pla samplesrc/hgr1test.pla $(PLVM02) $(PLASM)
	./$(PLASM) -AM < samplesrc/hgr1test.pla > samplesrc/hgr1test.a
	acme --setpc 4094 -o $(HGR1TEST) samplesrc/hgr1test.a
	./$(PLASM) -AM < samplesrc/hgr1.pla > samplesrc/hgr1.a
	acme --setpc 4094 -o $(HGR1) samplesrc/hgr1.a

$(ACORNOS): libsrc/acornos.pla $(PLVM) $(PLASM)
	./$(PLASM) -AM < libsrc/acornos.pla > libsrc/acornos.a
	acme --setpc 4094 -o $(ACORNOS) libsrc/acornos.a

dword: libsrc/dword.pla $(PLVM) $(PLASM)
	./$(PLASM) -AM < libsrc/dword.pla > libsrc/dword.a
	acme --setpc 4094 -o DWORD\#FE1000 libsrc/dword.a

hello:	samplesrc/hello.pla $(PLVM) $(PLASM)
	./$(PLASM) -AM < samplesrc/hello.pla > samplesrc/hello.a
	acme --setpc 4094 -o $(HELLO) samplesrc/hello.a
	./$(PLVM) HELLO

dump: samplesrc/dump.pla $(PLVM) $(PLASM)
	./$(PLASM) -AM < samplesrc/dump.pla > samplesrc/dump.a
	acme --setpc 4094 -o DUMP\#FE1000 samplesrc/dump.a

mode: samplesrc/mode.pla $(PLVM) $(PLASM)
	./$(PLASM) -AM < samplesrc/mode.pla > samplesrc/mode.a
	acme --setpc 4094 -o MODE\#FE1000 samplesrc/mode.a

hanoi: samplesrc/hanoi.pla $(PLVM) $(PLASM)
	./$(PLASM) -AM < samplesrc/hanoi.pla > samplesrc/hanoi.a
	acme --setpc 4094 -o HANOI\#FE1000 samplesrc/hanoi.a

pcw: samplesrc/pcw.pla $(PLVM) $(PLASM)
	./$(PLASM) -AM < samplesrc/pcw.pla > samplesrc/pcw.a
	acme --setpc 4094 -o PCW\#FE1000 samplesrc/pcw.a

plasma.ssd: $(PLVM32) $(PLVM128) hello testint dump mode hanoi pcw dword $(ACORNOS) samplesrc/pcw.bas
	beebasm -i skel.beebasm -do plasma.ssd
