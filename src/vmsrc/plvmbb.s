;**********************************************************
;*
;*            BBC B PLASMA INTERPETER
;*
;*             SYSTEM ROUTINES AND LOCATIONS
;*
;**********************************************************

	BBC = 1
	ERRNUM = $700
	ERRSTR = $701

;*
;* VM ZERO PAGE LOCATIONS
;*
	!SOURCE	"vmsrc/plvmzp.inc"
;*
;* INTERPRETER INSTRUCTION POINTER INCREMENT MACRO
;*
;* Note that for PLAS128, there are two instruction pointer high bytes:
;* - IPH is adjacent to IPL and together they form IP; this contains a
;*   'physical' address which can be used directly by the 6502
;* - IPHLOG is a separate byte and contains the 'logical' high byte of
;    the instruction pointer in the 64K bytecode bank
;* IPH and IPHLOG must be modified together
	!MACRO	INC_IP	{
	INY
	BNE	*+6
	INC	IPH
	INC	IPHLOG
	}
;*
;* INTERPRETER HEADER+INITIALIZATION
;*
;* TODO: Use $2000 as starting point for now; we can get cleverer later.
;* This will allow for DFS/ADFS workspace.
	*=	$2000
SEGBEGIN JMP	VMINIT
;*
;* Entered with A=new value for IPHLOG; update IPH and IPHLOG accordingly.
;*
;* TODO: We could potentially start by checking A against IPHLOG and doing
;* nothing if it's the same; this might save time paging in a bank which is
;* already selected.
;*
;* TODO: This can probably be optimised a bit
SETIPH
	STA	IPHLOG
	BIT	FLAG128
	BPL	SFTODORENAME
;* TODO: If we sacrifice 256 bytes for a lookup table we could reduce the
;* bit shifting overhead here.
				; Rotate top two bits of A to low two bits
	ASL
	ADC	#$00
	ASL
	ADC	#$00

	AND	#$03

;* TODO: For now we hard-code use of banks 4-7; we need to use a lookup
;* table later to allow arbitrary and non-contiguous banks to be used
;* (STA *+5:LDA TABLEBASE can be used to do the lookup without needing
;* to preserve X or Y if TABLEBASE is page-aligned)
	CLC
	ADC	#$04
	STA	$F4
	STA	$FE30

	LDA	IPHLOG
	AND	#$BF
	ORA	#$80

SFTODORENAME	STA	IPH
	RTS
;*
;* SYSTEM INTERPRETER ENTRYPOINT
;*
INTERP	LDA	#$00
	STA	FLAG128		; EXECUTE BYTECODE FROM MAIN RAM
	PLA
	CLC
	ADC	#$01
        STA     IPL
        PLA
	ADC	#$00
	JSR	SETIPH
	LDA	IFPH
	PHA			; SAVE ON STACK FOR LEAVE/RET
	LDA	IFPL
	PHA			; SAVE ON STACK FOR LEAVE/RET
	LDA	PPL		; SET FP TO PP
	STA	IFPL
	LDA	PPH
	STA	IFPH
	LDY	#$00
	JMP	FETCHOP
;*
;* ENTER INTO USER BYTECODE INTERPRETER
;*
IINTERP	LDA	#$80
	STA	FLAG128
	PLA
        STA     TMPL
        PLA
        STA     TMPH
	LDY	#$02
	LDA     (TMP),Y
	JSR	SETIPH
	DEY
	LDA     (TMP),Y
	STA	IPL
        DEY
	LDA	IFPH
	PHA			; SAVE ON STACK FOR LEAVE/RET
	LDA	IFPL
	PHA			; SAVE ON STACK FOR LEAVE/RET
	LDA	PPL		; SET FP TO PP
	STA	IFPL
	LDA	PPH
	STA	IFPH
	JMP	FETCHOP
;*
;* MUL TOS-1 BY TOS
;*
MUL	STY	IPY
	LDY	#$10
	LDA	ESTKL+1,X
	EOR	#$FF
	STA	TMPL
	LDA	ESTKH+1,X
	EOR	#$FF
	STA	TMPH
	LDA	#$00
	STA	ESTKL+1,X      	; PRODL
;	STA	ESTKH+1,X      	; PRODH
MULLP 	LSR	TMPH		; MULTPLRH
	ROR	TMPL		; MULTPLRL
	BCS	+
	STA	ESTKH+1,X      	; PRODH
	LDA	ESTKL,X		; MULTPLNDL
	ADC	ESTKL+1,X      	; PRODL
	STA	ESTKL+1,X
	LDA	ESTKH,X		; MULTPLNDH
	ADC	ESTKH+1,X      	; PRODH
+ 	ASL	ESTKL,X		; MULTPLNDL
	ROL	ESTKH,X		; MULTPLNDH
	DEY
	BNE	MULLP
	STA	ESTKH+1,X	; PRODH
	INX
	LDY	IPY
	JMP	NEXTOP
;*
;* INCREMENT TOS
;*
INCR 	INC	ESTKL,X
	BNE	INCR1
	INC	ESTKH,X
INCR1 	JMP	NEXTOP
;*
;* DECREMENT TOS
;*
DECR 	LDA	ESTKL,X
	BNE	DECR1
	DEC	ESTKH,X
DECR1 	DEC	ESTKL,X
	JMP	NEXTOP
;*
;* BITWISE COMPLIMENT TOS
;*
COMP 	LDA	#$FF
	EOR	ESTKL,X
	STA	ESTKL,X
	LDA	#$FF
	EOR	ESTKH,X
	STA	ESTKH,X
	JMP	NEXTOP
;*
;* OPCODE TABLE
;*
	!ALIGN	255,0
OPTBL 	!WORD	ZERO,ADD,SUB,MUL,DIV,MOD,INCR,DECR		; 00 02 04 06 08 0A 0C 0E
	!WORD	NEG,COMP,BAND,IOR,XOR,SHL,SHR,IDXW		; 10 12 14 16 18 1A 1C 1E
	!WORD	LNOT,LOR,LAND,LA,LLA,CB,CW,CS			; 20 22 24 26 28 2A 2C 2E
	!WORD	DROP,DUP,PUSH,PULL,BRGT,BRLT,BREQ,BRNE		; 30 32 34 36 38 3A 3C 3E
	!WORD	ISEQ,ISNE,ISGT,ISLT,ISGE,ISLE,BRFLS,BRTRU	; 40 42 44 46 48 4A 4C 4E
	!WORD	BRNCH,IBRNCH,CALL,ICAL,ENTER,LEAVE,RET,NEXTOP 	; 50 52 54 56 58 5A 5C 5E
	!WORD	LB,LW,LLB,LLW,LAB,LAW,DLB,DLW			; 60 62 64 66 68 6A 6C 6E
	!WORD	SB,SW,SLB,SLW,SAB,SAW,DAB,DAW			; 70 72 74 76 78 7A 7C 7E
;*
;* DIV TOS-1 BY TOS
;*
DIV 	JSR	_DIV
	LSR	DVSIGN		; SIGN(RESULT) = (SIGN(DIVIDEND) + SIGN(DIVISOR)) & 1
	BCS	NEG
	JMP	NEXTOP
;*
;* MOD TOS-1 BY TOS
;*
MOD	JSR	_DIV
	LDA	TMPL		; REMNDRL
	STA	ESTKL,X
	LDA	TMPH		; REMNDRH
	STA	ESTKH,X
	LDA	DVSIGN		; REMAINDER IS SIGN OF DIVIDEND
	BMI	NEG
	JMP	NEXTOP
;*
;* NEGATE TOS
;*
NEG 	LDA	#$00
	SEC
	SBC	ESTKL,X
	STA	ESTKL,X
	LDA	#$00
	SBC	ESTKH,X
	STA	ESTKH,X
	JMP	NEXTOP
;*
;* INTERNAL DIVIDE ALGORITHM
;*
_NEG 	LDA	#$00
	SEC
	SBC	ESTKL,X
	STA	ESTKL,X
	LDA	#$00
	SBC	ESTKH,X
	STA	ESTKH,X
	RTS
_DIV	STY	IPY
 	LDY	#$11		; #BITS+1
	LDA	#$00
	STA	TMPL		; REMNDRL
	STA	TMPH		; REMNDRH
	LDA	ESTKH,X
	AND	#$80
	STA	DVSIGN
	BPL	+
	JSR	_NEG
	INC	DVSIGN
+ 	LDA	ESTKH+1,X
	BPL	+
	INX
	JSR	_NEG
	DEX
	INC	DVSIGN
	BNE	_DIV1
+ 	ORA	ESTKL+1,X	; DVDNDL
	BEQ	_DIVEX
_DIV1 	ASL	ESTKL+1,X	; DVDNDL
	ROL	ESTKH+1,X	; DVDNDH
	DEY
	BCC	_DIV1
_DIVLP 	ROL	TMPL		; REMNDRL
	ROL	TMPH		; REMNDRH
	LDA	TMPL		; REMNDRL
	CMP	ESTKL,X		; DVSRL
	LDA	TMPH		; REMNDRH
	SBC	ESTKH,X		; DVSRH
	BCC	+
	STA	TMPH		; REMNDRH
	LDA	TMPL		; REMNDRL
	SBC	ESTKL,X		; DVSRL
	STA	TMPL		; REMNDRL
	SEC
+	ROL	ESTKL+1,X	; DVDNDL
	ROL	ESTKH+1,X	; DVDNDH
	DEY
	BNE	_DIVLP
_DIVEX	INX
	LDY	IPY
	RTS
;*
;* ADD TOS TO TOS-1
;*
ADD 	LDA	ESTKL,X
	CLC
	ADC	ESTKL+1,X
	STA	ESTKL+1,X
	LDA	ESTKH,X
	ADC	ESTKH+1,X
	STA	ESTKH+1,X
	INX
	JMP	NEXTOP
;*
;* SUB TOS FROM TOS-1
;*
SUB 	LDA	ESTKL+1,X
	SEC
	SBC	ESTKL,X
	STA	ESTKL+1,X
	LDA	ESTKH+1,X
	SBC	ESTKH,X
	STA	ESTKH+1,X
	INX
	JMP	NEXTOP
;
;*
;* SHIFT TOS LEFT BY 1, ADD TO TOS-1
;*
IDXW 	LDA	ESTKL,X
	ASL
	ROL	ESTKH,X
	CLC
	ADC	ESTKL+1,X
	STA	ESTKL+1,X
	LDA	ESTKH,X
	ADC	ESTKH+1,X
	STA	ESTKH+1,X
	INX
	JMP	NEXTOP
;*
;* BITWISE AND TOS TO TOS-1
;*
BAND 	LDA	ESTKL+1,X
	AND	ESTKL,X
	STA	ESTKL+1,X
	LDA	ESTKH+1,X
	AND	ESTKH,X
	STA	ESTKH+1,X
	INX
	JMP	NEXTOP
;*
;* INCLUSIVE OR TOS TO TOS-1
;*
IOR 	LDA	ESTKL+1,X
	ORA	ESTKL,X
	STA	ESTKL+1,X
	LDA	ESTKH+1,X
	ORA	ESTKH,X
	STA	ESTKH+1,X
	INX
	JMP	NEXTOP
;*
;* EXLUSIVE OR TOS TO TOS-1
;*
XOR 	LDA	ESTKL+1,X
	EOR	ESTKL,X
	STA	ESTKL+1,X
	LDA	ESTKH+1,X
	EOR	ESTKH,X
	STA	ESTKH+1,X
	INX
	JMP	NEXTOP
;*
;* SHIFT TOS-1 LEFT BY TOS
;*
SHL	STY	IPY
	LDA	ESTKL,X
	CMP	#$08
	BCC	SHL1
	LDY	ESTKL+1,X
	STY	ESTKH+1,X
	LDY	#$00
	STY	ESTKL+1,X
	SBC	#$08
SHL1 	TAY
	BEQ	SHL3
SHL2 	ASL	ESTKL+1,X
	ROL	ESTKH+1,X
	DEY
	BNE	SHL2
SHL3 	INX
	LDY	IPY
	JMP	NEXTOP
;*
;* SHIFT TOS-1 RIGHT BY TOS
;*
SHR	STY	IPY
	LDA	ESTKL,X
	CMP	#$08
	BCC	SHR2
	LDY	ESTKH+1,X
	STY	ESTKL+1,X
	CPY	#$80
	LDY	#$00
	BCC	SHR1
	DEY
SHR1 	STY	ESTKH+1,X
	SEC
	SBC	#$08
SHR2 	TAY
	BEQ	SHR4
	LDA	ESTKH+1,X
SHR3 	CMP	#$80
	ROR
	ROR	ESTKL+1,X
	DEY
	BNE	SHR3
	STA	ESTKH+1,X
SHR4 	INX
	LDY	IPY
	JMP	NEXTOP
;*
;* LOGICAL NOT
;*
LNOT	LDA	ESTKL,X
	ORA	ESTKH,X
	BEQ	LNOT1
	LDA	#$FF
LNOT1	EOR	#$FF
	STA	ESTKL,X
	STA	ESTKH,X
	JMP	NEXTOP
;*
;* LOGICAL AND
;*
LAND 	LDA	ESTKL+1,X
	ORA	ESTKH+1,X
	BEQ	LAND2
	LDA	ESTKL,X
	ORA	ESTKH,X
	BEQ	LAND1
	LDA	#$FF
LAND1 	STA	ESTKL+1,X
	STA	ESTKH+1,X
LAND2	INX
	JMP	NEXTOP
;*
;* LOGICAL OR
;*
LOR 	LDA	ESTKL,X
	ORA	ESTKH,X
	ORA	ESTKL+1,X
	ORA	ESTKH+1,X
	BEQ	LOR1
	LDA	#$FF
 	STA	ESTKL+1,X
	STA	ESTKH+1,X
LOR1	INX
	JMP	NEXTOP
;*
;* DUPLICATE TOS
;*
DUP 	DEX
	LDA	ESTKL+1,X
	STA	ESTKL,X
	LDA	ESTKH+1,X
	STA	ESTKH,X
	JMP	NEXTOP
;*
;* PUSH FROM EVAL STACK TO CALL STACK
;*
PUSH 	LDA	ESTKL,X
	PHA
	LDA	ESTKH,X
	PHA
	INX
	JMP	NEXTOP
;*
;* PULL FROM CALL STACK TO EVAL STACK
;*
PULL 	DEX
	PLA
	STA	ESTKH,X
	PLA
	STA	ESTKL,X
	JMP	NEXTOP
;*
;* CONSTANT
;*
ZERO 	DEX
	LDA	#$00
	STA	ESTKL,X
	STA	ESTKH,X
	JMP	NEXTOP
CB 	DEX
	+INC_IP
	LDA	(IP),Y
	STA	ESTKL,X
	LDA	#$00
	STA	ESTKH,X
	JMP	NEXTOP
;*
;* LOAD ADDRESS & LOAD CONSTANT WORD (SAME THING, WITH OR WITHOUT FIXUP)
;*
LA	=	*
CW	DEX
	+INC_IP
 	LDA	(IP),Y
	STA	ESTKL,X
	+INC_IP
 	LDA	(IP),Y
	STA	ESTKH,X
	JMP	NEXTOP
;*
;* CONSTANT STRING
;*
CS	DEX
	+INC_IP
	TYA			; NORMALIZE IP
	CLC
	ADC	IPL
	STA	IPL
	LDA	#$00
	TAY
	ADC	IPHLOG
	JSR	SETIPH
	LDA	(IP),Y
	TAY			; MAKE ROOM IN POOL AND SAVE ADDR ON ESTK
	EOR	#$FF
	CLC
	ADC	PPL
	STA	PPL
	STA	ESTKL,X
	LDA	#$FF
	ADC	PPH
	STA	PPH
	STA	ESTKH,X		; COPY STRING FROM AUX MEM BYTECODE TO MAIN MEM POOL
-	LDA	(IP),Y		; ALTRD IS ON,  NO NEED TO CHANGE IT HERE
	STA	(PP),Y		; ALTWR IS OFF, NO NEED TO CHANGE IT HERE
	DEY
	CPY	#$FF
	BNE	-
	INY
	LDA	(IP),Y		; SKIP TO NEXT OP ADDR AFTER STRING
	TAY
	JMP	NEXTOP
;*
;* LOAD VALUE FROM ADDRESS TAG
;*
LB 	LDA	ESTKL,X
	STA	TMPL
	LDA	ESTKH,X
	STA	TMPH
	STY	IPY
	LDY	#$00
	LDA	(TMP),Y
	STA	ESTKL,X
	STY	ESTKH,X
	LDY	IPY
	JMP	NEXTOP
LW 	LDA	ESTKL,X
	STA	TMPL
	LDA	ESTKH,X
	STA	TMPH
       	STY	IPY
	LDY	#$00
	LDA	(TMP),Y
	STA	ESTKL,X
	INY
	LDA	(TMP),Y
	STA	ESTKH,X
	LDY	IPY
	JMP	NEXTOP
;*
;* LOAD ADDRESS OF LOCAL FRAME OFFSET
;*
LLA 	+INC_IP
 	LDA	(IP),Y
	DEX
	CLC
	ADC	IFPL
	STA	ESTKL,X
	LDA	#$00
	ADC	IFPH
	STA	ESTKH,X
	JMP	NEXTOP
;*
;* LOAD VALUE FROM LOCAL FRAME OFFSET
;*
LLB 	+INC_IP
 	LDA	(IP),Y
	STY	IPY
	TAY
	DEX
	LDA	(IFP),Y
	STA	ESTKL,X
	LDA	#$00
	STA	ESTKH,X
	LDY	IPY
	JMP	NEXTOP
LLW 	+INC_IP
 	LDA	(IP),Y
	STY	IPY
	TAY
	DEX
	LDA	(IFP),Y
	STA	ESTKL,X
	INY
	LDA	(IFP),Y
	STA	ESTKH,X
	LDY	IPY
	JMP	NEXTOP
;*
;* LOAD VALUE FROM ABSOLUTE ADDRESS
;*
LAB 	+INC_IP
	LDA	(IP),Y
	STA	TMPL
	+INC_IP
	LDA	(IP),Y
	STA	TMPH
	STY	IPY
	LDY	#$00
	LDA	(TMP),Y
	DEX
	STA	ESTKL,X
	STY	ESTKH,X
	LDY	IPY
	JMP	NEXTOP
LAW 	+INC_IP
	LDA	(IP),Y
	STA	TMPL
	+INC_IP
	LDA	(IP),Y
	STA	TMPH
	STY	IPY
	LDY	#$00
	LDA	(TMP),Y
	DEX
	STA	ESTKL,X
	INY
	LDA	(TMP),Y
	STA	ESTKH,X
	LDY	IPY
	JMP	NEXTOP
;*
;* STORE VALUE TO ADDRESS
;*
SB 	LDA	ESTKL+1,X
	STA	TMPL
	LDA	ESTKH+1,X
	STA	TMPH
	LDA	ESTKL,X
	STY	IPY
	LDY	#$00
	STA	(TMP),Y
	INX
	INX
	LDY	IPY
	JMP	NEXTOP
SW 	LDA	ESTKL+1,X
	STA	TMPL
	LDA	ESTKH+1,X
	STA	TMPH
	STY	IPY
	LDY	#$00
	LDA	ESTKL,X
	STA	(TMP),Y
	INY
	LDA	ESTKH,X
	STA	(TMP),Y
	INX
	INX
	LDY	IPY
	JMP	NEXTOP
;*
;* STORE VALUE TO LOCAL FRAME OFFSET
;*
SLB 	+INC_IP
 	LDA	(IP),Y
	STY	IPY
	TAY
	LDA	ESTKL,X
	STA	(IFP),Y
	INX
	LDY	IPY
	JMP	NEXTOP
SLW 	+INC_IP
 	LDA	(IP),Y
	STY	IPY
	TAY
	LDA	ESTKL,X
	STA	(IFP),Y
	INY
	LDA	ESTKH,X
	STA	(IFP),Y
	INX
	LDY	IPY
	JMP	NEXTOP
;*
;* STORE VALUE TO LOCAL FRAME OFFSET WITHOUT POPPING STACK
;*
DLB 	+INC_IP
	LDA	(IP),Y
	STY	IPY
	TAY
	LDA	ESTKL,X
	STA	(IFP),Y
	LDY	IPY
	JMP	NEXTOP
DLW 	+INC_IP
	LDA	(IP),Y
	STY	IPY
	TAY
	LDA	ESTKL,X
	STA	(IFP),Y
	INY
	LDA	ESTKH,X
	STA	(IFP),Y
	LDY	IPY
	JMP	NEXTOP
;*
;* STORE VALUE TO ABSOLUTE ADDRESS
;*
SAB 	+INC_IP
	LDA	(IP),Y
	STA	TMPL
	+INC_IP
	LDA	(IP),Y
	STA	TMPH
	LDA	ESTKL,X
	STY	IPY
	LDY	#$00
	STA	(TMP),Y
	INX
	LDY	IPY
	JMP	NEXTOP
SAW 	+INC_IP
	LDA	(IP),Y
	STA	TMPL
	+INC_IP
	LDA	(IP),Y
	STA	TMPH
	STY	IPY
	LDY	#$00
	LDA	ESTKL,X
	STA	(TMP),Y
	INY
	LDA	ESTKH,X
	STA	(TMP),Y
	INX
	LDY	IPY
	JMP	NEXTOP
;*
;* STORE VALUE TO ABSOLUTE ADDRESS WITHOUT POPPING STACK
;*
DAB 	+INC_IP
	LDA	(IP),Y
	STA	TMPL
	+INC_IP
	LDA	(IP),Y
	STA	TMPH
	STY	IPY
	LDY	#$00
	LDA	ESTKL,X
	STA	(TMP),Y
	LDY	IPY
	JMP	NEXTOP
DAW 	+INC_IP
	LDA	(IP),Y
	STA	TMPL
	+INC_IP
	LDA	(IP),Y
	STA	TMPH
	STY	IPY
	LDY	#$00
	LDA	ESTKL,X
	STA	(TMP),Y
	INY
	LDA	ESTKH,X
	STA	(TMP),Y
	LDY	IPY
	JMP	NEXTOP
;*
;* COMPARES
;*
ISEQ	LDA	ESTKL,X
	CMP	ESTKL+1,X
	BNE	ISFLS
	LDA	ESTKH,X
	CMP	ESTKH+1,X
	BNE	ISFLS
ISTRU	LDA	#$FF
	INX
	STA	ESTKL,X
	STA	ESTKH,X
	JMP	NEXTOP
;
ISNE	LDA	ESTKL,X
	CMP	ESTKL+1,X
	BNE	ISTRU
	LDA	ESTKH,X
	CMP	ESTKH+1,X
	BNE	ISTRU
ISFLS 	LDA	#$00
	INX
	STA	ESTKL,X
	STA	ESTKH,X
	JMP	NEXTOP
;
ISGE	LDA	ESTKL+1,X
	CMP	ESTKL,X
	LDA	ESTKH+1,X
	SBC	ESTKH,X
	BVC	ISGE1
	EOR	#$80
ISGE1 	BPL	ISTRU
	BMI	ISFLS
;
ISGT	LDA	ESTKL,X
	CMP	ESTKL+1,X
	LDA	ESTKH,X
	SBC	ESTKH+1,X
	BVC	ISGT1
	EOR	#$80
ISGT1 	BMI	ISTRU
	BPL	ISFLS
;
ISLE	LDA	ESTKL,X
	CMP	ESTKL+1,X
	LDA	ESTKH,X
	SBC	ESTKH+1,X
	BVC	ISLE1
	EOR	#$80
ISLE1 	BPL	ISTRU
	BMI	ISFLS
;
ISLT	LDA	ESTKL+1,X
	CMP	ESTKL,X
	LDA	ESTKH+1,X
	SBC	ESTKH,X
	BVC	ISLT1
	EOR	#$80
ISLT1 	BMI	ISTRU
	BPL	ISFLS
;*
;* BRANCHES
;*
BRTRU 	INX
	LDA	ESTKH-1,X
	ORA	ESTKL-1,X
	BNE	BRNCH
NOBRNCH	+INC_IP
	+INC_IP
	JMP	NEXTOP
BRFLS 	INX
	LDA	ESTKH-1,X
	ORA	ESTKL-1,X
	BNE	NOBRNCH
BRNCH	LDA	IPHLOG
	STA	TMPH
	LDA	IPL
	+INC_IP
	CLC
	ADC	(IP),Y
	STA	TMPL
	LDA	TMPH
	+INC_IP
	ADC	(IP),Y
	; TODONOWWRAPWRISK
	JSR	SETIPH
	LDA	TMPL
	STA	IPL
	DEY
	DEY
	JMP	NEXTOP
BREQ 	INX
	LDA	ESTKL-1,X
	CMP	ESTKL,X
	BNE	NOBRNCH
	LDA	ESTKH-1,X
	CMP	ESTKH,X
	BEQ	BRNCH
	BNE	NOBRNCH
BRNE 	INX
	LDA	ESTKL-1,X
	CMP	ESTKL,X
	BNE	BRNCH
	LDA	ESTKH-1,X
	CMP	ESTKH,X
	BEQ	NOBRNCH
	BNE	BRNCH
BRGT 	INX
	LDA	ESTKL-1,X
	CMP	ESTKL,X
	LDA	ESTKH-1,X
	SBC	ESTKH,X
	BMI	BRNCH
	BPL	NOBRNCH
BRLT 	INX
	LDA	ESTKL,X
	CMP	ESTKL-1,X
	LDA	ESTKH,X
	SBC	ESTKH-1,X
	BMI	BRNCH
	BPL	NOBRNCH
IBRNCH	LDA	IPL
	CLC
	ADC	ESTKL,X
	STA	IPL
	LDA	IPHLOG
	ADC	ESTKH,X
	; TODONOWWRAPRISK
	JSR	SETIPH
	INX
	JMP	NEXTOP
; TODO: CALL and ICAL both stack FLAG128; this is necessary for when mixing bytecode
; in main RAM and banked RAM. The Apple II implementation handles this via CALL(X) and
; ICAL(X) updating the fetch loop to use the right opcode table, i.e. the state is
; implicit in whether we're executing CALL or CALLX (ditto for ICAL/ICALX). It might
; be better if we do that to avoid burning an extra byte of CPU stack for each call,
; but this will do for now. (We don't need so many X opcodes for our banked implementation
; so we don't currently have separate opcode tables.)
;*
;* CALL INTO ABSOLUTE ADDRESS (NATIVE CODE)
;*
CALL 	+INC_IP
	LDA	(IP),Y
	STA	CALLADR+1
	+INC_IP
	LDA	(IP),Y
	STA	CALLADR+2
	LDA	IPHLOG
	PHA
	LDA	IPL
	PHA
	TYA
	PHA
	LDA	FLAG128
	PHA
CALLADR	JSR	$FFFF
	PLA
	STA	FLAG128
	PLA
	TAY
	PLA
	STA	IPL
	PLA
	JSR	SETIPH
	JMP	NEXTOP
;*
;* INDIRECT CALL TO ADDRESS (NATIVE CODE)
;*
ICAL 	LDA	ESTKL,X
	STA	ICALADR+1
	LDA	ESTKH,X
	STA	ICALADR+2
	INX
	LDA	IPHLOG
	PHA
	LDA	IPL
	PHA
	TYA
	PHA
	LDA	FLAG128
	PHA
ICALADR	JSR	$FFFF
	PLA
	STA	FLAG128
	PLA
	TAY
	PLA
	STA	IPL
	PLA
	JSR	SETIPH
	JMP	NEXTOP
;*
;* ENTER FUNCTION WITH FRAME SIZE AND PARAM COUNT
;*
ENTER	INY
	LDA	(IP),Y
	PHA			; SAVE ON STACK FOR LEAVE
	EOR	#$FF
	SEC
	ADC	PPL
	STA	PPL
	STA	IFPL
	LDA	#$FF
	ADC	PPH
	STA	PPH
	STA	IFPH
	INY
	LDA	(IP),Y
	ASL
	TAY
	BEQ	+
-	LDA	ESTKH,X
	DEY
	STA	(IFP),Y
	LDA	ESTKL,X
	INX
	DEY
	STA	(IFP),Y
	BNE	-
+	LDY	#$02
	JMP	NEXTOP
;*
;* LEAVE FUNCTION
;*
LEAVE 	PLA
	CLC
	ADC	IFPL
	STA	PPL
	LDA	#$00
	ADC	IFPH
	STA	PPH
 	PLA			; RESTORE PREVIOUS FRAME
	STA	IFPL
	PLA
	STA	IFPH
 	RTS
;
RET	LDA	IFPL		; DEALLOCATE POOL
	STA	PPL
	LDA	IFPH
	STA	PPH
 	PLA			; RESTORE PREVIOUS FRAME
	STA	IFPL
	PLA
	STA	IFPH
	RTS
A1CMD	!SOURCE	"vmsrc/bbcmd.a"

BRKHND
	LDY	#0
	LDA	($FD),Y
	STA	ERRNUM
ERRCPY	INY
	LDA	($FD),Y
	BEQ	ERRCPD
	STA	ERRSTR,Y
	BNE	ERRCPY
ERRCPD	DEY
	STY	ERRSTR
	;* ERRNUM now holds the error number
	;* ERRSTR now holds the error message as a standard PLASMA string
	
	LDX	#$FF
	TXS
        LDX	#ESTKSZ/2	; INIT EVAL STACK INDEX
	JSR	BRKJMP
	;* TODO: Better "abort" behaviour
	LDA	#'!'
	JSR	$FFEE
BRKLP	JMP	BRKLP
BRKJMP	JMP ($400) ;* TODO: Better address



	LDA	#65
	JSR	$FFEE
	JMP	BRKHND

SEGEND	=	*
;* TODO: Tidy up zero page use
VMINIT	LDY	#$20		; INSTALL PAGE 0 FETCHOP ROUTINE
- 	LDA	PAGE0-1,Y
	STA	DROP-1,Y
	DEY
	BNE	-
	LDA	#$84
	JSR	$FFF4
	STX	PPL
	STX	IFPL		; INIT FRAME POINTER
	STY	PPH
	STY	IFPH
	STY	HIMEMH
	LDA	#<SEGEND	; SAVE HEAP START
	STA	SRCL
	LDX	#>SEGEND
	STX	SRCH
	INX
	INX
	CPX	IFPH
	BCS	INITNOROOM
        LDX	#ESTKSZ/2	; INIT EVAL STACK INDEX
;* Install BRK handler
	LDA	#<BRKHND
	STA	$0202
	LDA	#>BRKHND
	STA	$0203
	JMP	A1CMD
INITNOROOM	
	BRK
	!BYTE	$00
	!TEXT	"No room"
	BRK
PAGE0	=	*
       	!PSEUDOPC	DROP  {
;*
;* INTERP BYTECODE INNER LOOP
;*
	INX			; DROP
	INY			; NEXTOP
	BEQ	NEXTOPH
	LDA	$FFFF,Y		; FETCHOP @ $F3, IP MAPS OVER $FFFF @ $F4
	STA	OPIDX
	JMP	(OPTBL)
NEXTOPH	INC	IPH
	INC	IPHLOG
	BNE	FETCHOP

; TODO: HACKED ABOUT VERSION TO FORM A *SKETCH* OF 'BAS128'-STYLE IMPLEMENTATION
; IPH IS NO LONGER OVERLAID ON THIS CODE, BUT IPL WOULD STILL BE
; TODO: AND OF COURSE EVERY LDA (IP),Y WOULD NEED MODIFICATION
; WE MIGHT WANT TO USE A MACRO OR (PROB IDEALLY NOT FOR PERFORMANCE) USE A SUBROUTINE
; - BASICALLY EVERYWHERE THE INC_IP MACRO IS USED IS PROBABLY AFFECTED (NOTE THERE'S
; NO STORING, AS WE DON'T MODIFY THE BYTECODE AT RUN TIME)
; - I DO WONDER IF WE CAN TAKE ADVANTAGE OF THE FACT THAT WE KNOW THE FETCH LOOP
; BELOW HAS PAGED IN THE CORRECT 16K BANK ALREADY, SO WE ONLY NEED TO FORCE THE TOP
; TWO BITS OF THE ADDRESS TO %10 - AND IN FACT I THINK THAT ADDRESS MIGHT ALREADY
; BE AVAILABLE IN ZP AS THE IPL/IPHOVERLAY PAIR READY FOR USE, SO WE MAY NOT HAVE
; TO PAY ANY EXTRA COST AT ALL THERE (OR DO ANY WORK CHANGING CODE)?!
; TODO: IN FACT, SINCE MOST EXECUTION IS SEQUENTIAL (AND WE'D PROBABLY REFUSE TO ALLOCATE
; ACROSS 16K BOUNDARIES AS NOTED BELOW RE LEAVING LAST 256 BYTES FREE), WE CAN
; POTENTIALLY AVOID DOING THE 64->16K MAPPING ON EVERY INSTRUCTION FETCH AND ONLY DO
; IT WHEN WE MODIFY THE INSTRUCTION POINTER VIA A JUMP OR VIA THE NEXTOPH CODE) - IF
; THE OS DOESN'T KEEP PAGING "THE CURRENT LANGUAGE ROM" BACK IN (BUT INSTEAD REVERTS
; TO PREVIOUS ROM AFTER ANY PAGING IN FOR SERVICE CALL HANDLING) WE CAN AVOID THE
; NEED TO POKE $F4/$FE30 IN THE DISPATCH LOOP AS WELL (AND A QUICK LOOK OVER THE OS 1.2
; DISASSEMBLY SUGGESTS IT DOES INDEED BEHAVE LIKE THAT, SO IT'S *PROBABLY* OK)
; TODO: OUR ALLOCXHEAP MIGHT WANT TO AVOID ALLOCATING ANYTHING IN THE FIRST N BYTES OF
; EACH 16K BANK TO AVOID THE RISK OF IT LOOKING LIKE A VALID ROM IMAGE TO THE OS
; TODO: WE COULD OF COURSE JUST 'ADD Y IN' TO THE ADDRESS TO AVOID THE WRAPPING AT
; TOP OF 16K PROBLEM, BUT WE COULD ALTERNATIVELY LEAVE THE LAST 256 BYTES OF EACH
; BANK FREE (LAST 255? WHATEVER...) - ,Y THEN CAN'T CAUSE WRAPPING - HMM, ACTUALLY,
; I THINK WE CAN ALLOCATE RIGHT UP TO THE END OF THE BANK - AS LONG AS NO INDIVIDUAL
; ALLOCATION (AND THEREFORE NO FUNCTION DEFINITION) CAN WRAP ACROSS THE END OF A BANK,
; THE ,Y CAN'T CAUSE WRAPPING
;*
;* INTERP BYTECODE INNER LOOP
;*
!IFDEF NOTDEF {
	INX			; DROP
	INY			; NEXTOP
	BEQ	NEXTOPH
	LDA	IPH
	TAX 	; TODO WE AREN'T ALLOWED TO CORRUPT X...
	AND	#%10000000
	ORA	#%01000000
	STA	IPHOVERLAY

	LDA	BANKTABLE,X	; ONLY TOP TWO BITS RELEVANT BUT SACRIFICE 256 BYTES FOR SPEED
				; (OR ROL A:ROL A:ROL A:AND #%11:TAX OR OSMETHING, BUT THAT'S SLOW *AND* CORRUPTS A)
	STA	$F4
	STA	$FE30

	; TODO: Y OFFSET IS TRICKY HERE AS IT MIGHT WRAP INTO NEXT BANK
	LDA	$FFFF,Y		; FETCHOP, LOW BYTE OF ADDRESS IS IPL, HIGH IS IPHOVERLAY - IPH IS SEPARATE ZP
	STA	OPIDX
	JMP	(OPTBL)
NEXTOPH	INC	IPH
	BNE	FETCHOP
	}
}
