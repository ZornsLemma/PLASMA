;**********************************************************
;*
;*            BBC B PLASMA INTERPETER
;*
;*             SYSTEM ROUTINES AND LOCATIONS
;*
;**********************************************************

	BBC = 1
!IFDEF PLAS128 {
	RAMBANK = $400		; 4 byte table of RAM bank numbers
	RAMBANKCOUNT = $404
}
	ERRFP  = $405		; 2 bytes
      ; ERRJB  = $407		; 2 bytes
	ERRNUM = $700
	ERRSTR = $701

;*
;* VM ZERO PAGE LOCATIONS
;*
	!SOURCE	"vmsrc/plvmzp.inc"
;*
;* INTERPRETER INSTRUCTION POINTER INCREMENT MACRO
;*
	!MACRO	INC_IP	{
	INY
	BNE	*+4
	INC	IPH
	}
;*
;* INTERPRETER HEADER+INITIALIZATION
;*
	*=	START
SEGBEGIN JMP	VMINIT

;*
;* SYSTEM INTERPRETER ENTRYPOINT
;* (PLAS128: executes bytecode from main RAM)
;*
INTERP	PLA
	CLC
	ADC	#$01
        STA     IPL
        PLA
	ADC	#$00
	STA	IPH
!IFDEF PLAS128 {
	LDA	IFPH
	PHA			; SAVE ON STACK FOR LEAVE/RET
	LDA	IFPL
	PHA			; SAVE ON STACK FOR LEAVE/RET
	LDA	PPL		; SET FP TO PP
	STA	IFPL
	LDA	PPH
	STA	IFPH
}
	LDY	#$00
	JMP	FETCHOP
;*
;* ENTER INTO USER BYTECODE INTERPRETER
;* (PLAS128: executes bytecode from banked RAM)
;*
;* PLAS128: loadmod() and allocxheap() don't allow a single module's bytecode to
;* straddle a 16K bank boundary. Calls between functions are handled via
;* a JSR to the function header in main RAM; each new function will call
;* back into IINTERP. This means that we can decide which bank to page in
;* here (interpreting IP as a logical address in the banked RAM) and then
;* we're good to stick with that bank; we convert IP into the
;* corresponding physical address in the sideways RAM area here and just
;* work with that while executing the function.
;*
IINTERP	PLA
        STA     TMPL
        PLA
        STA     TMPH
	LDY	#$02
	LDA     (TMP),Y

	STA	IPH
!IFDEF PLAS128 {
;* TODO: If we sacrifice 256 bytes for a lookup table we could reduce the
;* bit shifting overhead here.
				; Rotate top two bits of A to low two bits
	ASL
	ADC	#$00
	ASL
	ADC	#$00
	AND	#$03
	TAY
	LDA	RAMBANK,Y
	STA	$F4
	STA	$FE30
	LDA	IPH
	AND	#$BF		; Force top two bits to %10
	ORA	#$80
	STA	IPH

	LDY	#$01
}
!IFNDEF PLAS128 {
	DEY
}
	
	LDA     (TMP),Y
	STA	IPL
        DEY
!IFDEF PLAS128 {
	LDA	IFPH
	PHA			; SAVE ON STACK FOR LEAVE/RET
	LDA	IFPL
	PHA			; SAVE ON STACK FOR LEAVE/RET
	LDA	PPL		; SET FP TO PP
	STA	IFPL
	LDA	PPH
	STA	IFPH
}
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
!IFNDEF PLAS128 {
	STA	ESTKL,X
}
	LDA	#$00
	TAY
	ADC	IPH
	STA	IPH
!IFNDEF PLAS128 {
	STA	ESTKH,X
}
!IFDEF PLAS128 {
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
}
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
BRNCH	LDA	IPH
	STA	TMPH
	LDA	IPL
	+INC_IP
	CLC
	ADC	(IP),Y
	STA	TMPL
	LDA	TMPH
	+INC_IP
	ADC	(IP),Y
	STA	IPH
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
	LDA	IPH
	ADC	ESTKH,X
	STA	IPH
	INX
	JMP	NEXTOP
;*
;* CALL INTO ABSOLUTE ADDRESS (NATIVE CODE)
;*
CALL 	+INC_IP
	LDA	(IP),Y
	STA	CALLADR+1
	+INC_IP
	LDA	(IP),Y
	STA	CALLADR+2
	LDA	IPH
	PHA
	LDA	IPL
	PHA
	TYA
	PHA
!IFDEF PLAS128 {
	LDA	$F4
	PHA
}
CALLADR	JSR	$FFFF		; PLAS128: may page in another bank
!IFDEF PLAS128 {
	PLA
	STA	$F4
	STA	$FE30
}
	PLA
	TAY
	PLA
	STA	IPL
	PLA
	STA	IPH
	JMP	NEXTOP
;*
;* INDIRECT CALL TO ADDRESS (NATIVE CODE)
;*
ICAL 	LDA	ESTKL,X
	STA	ICALADR+1
	LDA	ESTKH,X
	STA	ICALADR+2
	INX
	LDA	IPH
	PHA
	LDA	IPL
	PHA
	TYA
	PHA
!IFDEF PLAS128 {
	LDA	$F4
	PHA
}
ICALADR	JSR	$FFFF		; PLAS128: may page in another bank
!IFDEF PLAS128 {
	PLA
	STA	$F4
	STA	$FE30
}
	PLA
	TAY
	PLA
	STA	IPL
	PLA
	STA	IPH
	JMP	NEXTOP
;*
;* ENTER FUNCTION WITH FRAME SIZE AND PARAM COUNT
;*
ENTER	INY
	LDA	(IP),Y
	PHA			; SAVE ON STACK FOR LEAVE
	EOR	#$FF
	SEC
!IFNDEF PLAS128 {
	ADC	IFPL
}
!IFDEF PLAS128 {
	ADC	PPL
	STA	PPL
}
	STA	IFPL
!IFNDEF PLAS128 {
	BCS	+
	DEC	IFPH
+	
}
!IFDEF PLAS128 {
	LDA	#$FF
	ADC	PPH
	STA	PPH
	STA	IFPH
}
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
!IFDEF PLAS128 {
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
}
	STA	IFPL
!IFDEF PLAS128 {
	PLA
	STA	IFPH
	RTS
}
!IFNDEF PLAS128 {
	BCS	LIFPH
	RTS
LIFPH	INC	IFPH
RET	RTS
}
; Compiled PLASMA code
A1CMD	
!ifndef PLAS128 {
	!SOURCE "vmsrc/32cmd.a"
}
!ifdef PLAS128  {
	!SOURCE "vmsrc/128cmd.a"
}

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
BRKJMP	JMP	(ERRFP)

SEGEND	=	*
;* TODO: Tidy up zero page use

;* TODO: Does PLAS128 need to refuse to run if Tube is active? Merely having
;* load address set to &FFxxxx doesn't seem to make it work properly. Ah,
;* it's probably because my OSFILE command has 0 for high order bits - I can
;* probably fix that.
VMINITPOSTRELOC
	LDY	#$10		; INSTALL PAGE 0 FETCHOP ROUTINE
- 	LDA	PAGE0-1,Y
	STA	DROP-1,Y
	DEY
	BNE	-

!IFDEF PLAS128 {
;* Locate sideways RAM banks
;* TODO: Might be nice to allow these to be specified on command line
	LDY	#$00
	LDX	#$00
FINDRAMLP
	LDA	$2A1,X
	AND	#$C0
	BNE	SKIPBANK	; ONLY CONSIDER BANKS WITH NO LANGUAGE OR SERVICE ENTRY
	STY	$F4
	STY	$FE30
	INC	$8008		; BINARY VERSION NUMBER
	LDA	$8008
	DEC	$8008
	CMP	$8008
	BEQ	SKIPBANK	; IT'S NOT RAM
	TYA
	STA	RAMBANK,X
	INX
	CPX	#$04
	BEQ	FINDRAMDONE
SKIPBANK
	INY
	CPY	#$10
	BNE	FINDRAMLP
FINDRAMDONE
	TXA
	BNE	SOMERAM
	BRK
	!BYTE	$80
	!TEXT	"No sideways RAM found"
	BRK
SOMERAM	STX	RAMBANKCOUNT
}

	;* If we're running on a second processor, we use memory up to $F800, whatever
	;* OSBYTE $84 says. TODONOW: Make sure mode change code doesn't "undo" this...
	LDA	#$84
	JSR	$FFF4
	LDA	#>START
	CMP	#$0E
	BCS	NOTTUBE
	LDY	#$F8
NOTTUBE
	STX	IFPL		; INIT FRAME POINTER
	STY	IFPH
!IFDEF PLAS128 {
	STX	PPL
	STY	PPH
}
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
	BNE	FETCHOP
}

VMINIT
	LDX	#$FF
	TXS

				; RELOCATE CODE TO OSHWM
	DELTA   = SCRATCH
	CODEP   = SCRATCH+1
	CODEPL  = CODEP
	CODEPH  = CODEP+1
	DELTAP  = SCRATCH+3
	DELTAPL = DELTAP
	DELTAPH = DELTAP+1
	COUNT	= SCRATCH+5
	COUNTL  = COUNT
	COUNTH  = COUNT+1
	LDA	#$83
	JSR	$FFF4
	CPY	#(>START)+1
	BCC	RELOCOK		; We don't support relocating upwards
	BRK
	!BYTE	$80
	!TEXT	"PAGE too high"
	BRK
RELOCOK
	TYA
	STA	DSTH
	SEC
	SBC	#>START
	STA	DELTA
	LDA	#>START
	STA	CODEPH
	STA	SRCH
	STA	CODEPH
	LDA	#0
	TAY
	STA	DSTL
	STA	SRCL
	STA	CODEPL
	LDA	#<VMRELOC
	STA	DELTAPL
	LDA	#>VMRELOC
	STA	DELTAPH
	LDA	VMRELOCCOUNT
	STA	COUNTL
	LDA	VMRELOCCOUNT+1
	STA	COUNTH
	; If there are no relocations, the fix up data hasn't been appended.
	; Justy carry on without relocating.
	ORA	COUNTL
	BNE	DORELOC
	JMP	VMINITPOSTRELOC
DORELOC

	; None of the following code can contain absolute addresses,
	; otherwise it will be modified while it's executing and may crash.
	; This is why we have to copy VMRELOCCOUNT into zero page.

	; Fix up the absolute addresses in the VM code in place
RELPATCHLP
	LDA	(DELTAP),Y
	BEQ	PAGEADVANCE
	CLC
	ADC	CODEPL
	STA	CODEPL
	BCC	RELPATCHCC
	INC	CODEPH
RELPATCHCC
	LDA	(CODEP),Y
	CLC
	ADC	DELTA
	STA	(CODEP),Y
RELPATCHNEXT
	INC	DELTAPL
	BNE	RELPATCHNE
	INC	DELTAPH
RELPATCHNE
	LDA	COUNTL
	BNE	RELPATCHNE2
	DEC	COUNTH
RELPATCHNE2
	DEC	COUNTL
	BNE	RELPATCHLP
	LDA	COUNTH
	BNE	RELPATCHLP

	; Now copy the code down to OSHWM. We must not copy over the top of
	; this code while it's executing! This is why it's right at the end,
	; and we're precise about how many bytes we copy.
	BYTESTOCOPY = VMINIT-START
	LDA	#>BYTESTOCOPY
	STA	COUNTH
	LDY	#<BYTESTOCOPY
	STY	COUNTL
	BEQ	RELCOPYLP
	INC	COUNTH
	LDY	#0
RELCOPYLP
	LDA	(SRC),Y
	STA	(DST),Y
	INY
	BNE	RELCOPYNOINC
	INC	SRCH
	INC	DSTH
RELCOPYNOINC
	DEC	COUNTL
	BNE	RELCOPYLP
	DEC	COUNTH
	BNE	RELCOPYLP

	; Now execute the relocated code; this absolute address will have
	; been patched up.
	JMP	VMINITPOSTRELOC

PAGEADVANCE
	INC	CODEPH
	BNE	RELPATCHNEXT	; ALWAYS BRANCHES

VMRELOCCOUNT
	!WORD $0000
VMRELOC				; MUST BE LAST LINE OF FILE
