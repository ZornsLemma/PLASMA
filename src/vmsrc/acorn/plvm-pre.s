;**********************************************************
;*
;*          ACORN PLASMA INTERPETER
;*
;*              SYSTEM ROUTINES AND LOCATIONS
;*
;**********************************************************
;* TODO: I haven't got *all* self-modifying code covered by SELFMODIFY; I
;* haven't ported one or two SELFMODIFY references across from the Apple II
;* code. Probably just review code myself if/when a ROM build is supported.
SELFMODIFY = 1

;* If this is 1, code is included when lowering IFP/PP to ensure they don't
;* drop below the top of the heap. This is fairly cheap; the fncall benchmark
;* slows down by <2% and ENTER is the main opcode penalised by this checking,
;* so most code should see even less cost. (CS is also penalised, but only when
;* the string isn't already in the pool, and it's relatively slow anyway.)
CHECKPARAMETERSTACK = 1

;* If this is 1, code is included in ENTER and CALL (when the called function
;* returns) to check that X (the ESTK pointer) has a valid value; if it doesn't
;* an error is generated. This is an imperfect but relatively cheap way to
;* check for stack underflow/overflow and does seem to help catch problems in
;* practice. (This is much more likely when using the new #n feature to specify
;* the number of return values for a function, as getting a mismatch between
;* caller and callee is possible.) This slows the fncall benchmark down by 1.4%.
CHECKEXPRESSIONSTACK = 1

;*
;* VM ZERO PAGE LOCATIONS
;*
	!SOURCE	"vmsrc/plvmzp.inc"
DROP    =       $1F
NEXTOP  =       $20
FETCHOP =       NEXTOP+1
IP      =       FETCHOP+1
IPL     =       IP
IPH     =       IPL+1
OPIDX   =       FETCHOP+6
OPPAGE  =       OPIDX+1
;*
;* ACORN OS AND VM CONSTANTS
;*
	!SOURCE "vmsrc/acorn/acornc.inc"

	!MACRO	CHECKVSHEAPHIGHINA .P {
		!IF CHECKPARAMETERSTACK {
			CMP	HEAPH
			BEQ	.CHECKLOW
			BCS	.OK
.FAIL
			JMP	HITHEAP
.CHECKLOW
			LDA	.P
			CMP	HEAPL
			BCC	.FAIL
.OK
		}
	}

	!MACRO	CHECKVSHEAP .P {
		!IF CHECKPARAMETERSTACK {
			LDA	.P+1
			+CHECKVSHEAPHIGHINA .P
		}
	}
;*
;* INTERPRETER HEADER+INITIALIZATION
;*
	*=	START
SEGBEGIN JMP	VMINIT

INITNOROOM
HITHEAP
	BRK
	!BYTE	$00		; same error number as BASIC "No room"
	!TEXT	"No room"
	BRK
;*
;* INCREMENT TOS
;*
INCR    INC     ESTKL,X
        BEQ     +
        JMP     NEXTOP
+	INC     ESTKH,X
        JMP     NEXTOP
;*
;* DECREMENT TOS
;*
DECR    LDA     ESTKL,X
        BEQ     +
        DEC     ESTKL,X
        JMP     NEXTOP
+	DEC     ESTKL,X
        DEC     ESTKH,X
        JMP     NEXTOP
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
	LDY	IPY
	JMP     DROP
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
;* DIVMOD TOS-1 BY TOS
;*
DIVMOD  JSR     _DIV
        LSR     DVSIGN          ; SIGN(RESULT) = (SIGN(DIVIDEND) + SIGN(DIVISOR)) & 1
        BCC     +
        JSR     _NEG
	;* SFTODO: FOLLOWING CHUNK OF CODE LOOKS RATHER LIKE PART OF 'MOD', CAN WE FACTOR IT OUT? I DON'T THINK PERFORMANCE IS CRITICAL HERE, A BRANCH/JUMP IS NEGLIGIBLE COMPARED TO THE OVERHEAD OF DOING A DIVISION...
+       DEX
        LDA     TMPL            ; REMNDRL
        STA     ESTKL,X
        LDA     TMPH            ; REMNDRH
        STA     ESTKH,X
        LDA     DVSIGN          ; REMAINDER IS SIGN OF DIVIDEND
        BMI     NEG
        JMP     NEXTOP
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
ANRTS	RTS			; TODO: GET RID OF ANRTS LABEL IF NOT USED
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
;* OPCODE TABLE
;*
;* This has to be page-aligned; to avoid wasting a lot of space to achieve
;* this the preceding code has been carefully chosen to exactly fill the
;* gap between the initial 'JMP VMINIT' and this table. (If we were prepared
;* to use the Acorn OS's ability to specify a distinct execution address for
;* a binary we could simply put this table right at the beginning and avoid
;* any potential wasted space, but keeping track of the execution address
;* through assembly to putting a file on an emulated disc image is more
;* effort than it's worth.)
;*
;* TODO: Check every now and again that this alignment is still "efficient"
;* on all builds.
;*
	!ALIGN	255,0
OPTBL 	!WORD	ZERO,ADD,SUB,MUL,DIV,MOD,INCR,DECR		; 00 02 04 06 08 0A 0C 0E
	!WORD	NEG,COMP,BAND,IOR,XOR,SHL,SHR,IDXW		; 10 12 14 16 18 1A 1C 1E
	!WORD	LNOT,LOR,LAND,LA,LLA,CB,CW,CS			; 20 22 24 26 28 2A 2C 2E
	!WORD	DROP,DUP,NEXTOP,DIVMOD,BRGT,BRLT,BREQ,BRNE	; 30 32 34 36 38 3A 3C 3E
	!WORD	ISEQ,ISNE,ISGT,ISLT,ISGE,ISLE,BRFLS,BRTRU	; 40 42 44 46 48 4A 4C 4E
	!WORD	BRNCH,IBRNCH,CALL,ICAL,ENTER,LEAVE,RET,CFFB 	; 50 52 54 56 58 5A 5C 5E
	!WORD	LB,LW,LLB,LLW,LAB,LAW,DLB,DLW			; 60 62 64 66 68 6A 6C 6E
	!WORD	SB,SW,SLB,SLW,SAB,SAW,DAB,DAW			; 70 72 74 76 78 7A 7C 7E

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

!IFNDEF PLAS128 {
	STA	IPH
	DEY
} ELSE {
	; This code must be kept consistent with memxcpy()

	; Copy top two bits of A to low two bits of Y and force top two bits of
	; A to %10. We then page in our RAM bank Y (0-3) and use A as IPH.
	; Note that Y=2 and the flags reflect the current value in A.
	BMI	+
	LDY	#$00
+	; b1 of Y is now b7 of A. ROL A so N flag reflects b7 of original A.
	ROL
	BPL	++
	INY
++	; Low two bits of Y now contain top two bits of original A. We need to
	; ROR A to undo the ROL A; we take this opportunity to force its high
	; bit to 1.
	SEC
	ROR
	; We can now clear b6 of A and we have A and Y set how we want them.
	AND	#$BF
	STA 	IPH

	LDA	RAMBANK,Y
	STA	$F4
	STA	$FE30

	LDY	#$01
}
	
	LDA     (TMP),Y
	STA	IPL
        DEY
	JMP	FETCHOP
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
	JMP     DROP
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
	JMP     DROP
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
	JMP     DROP
;*
;* BITWISE AND TOS TO TOS-1
;*
BAND 	LDA	ESTKL+1,X
	AND	ESTKL,X
	STA	ESTKL+1,X
	LDA	ESTKH+1,X
	AND	ESTKH,X
	STA	ESTKH+1,X
	JMP     DROP
;*
;* INCLUSIVE OR TOS TO TOS-1
;*
IOR 	LDA	ESTKL+1,X
	ORA	ESTKL,X
	STA	ESTKL+1,X
	LDA	ESTKH+1,X
	ORA	ESTKH,X
	STA	ESTKH+1,X
	JMP	DROP
;*
;* EXCLUSIVE OR TOS TO TOS-1
;*
XOR 	LDA	ESTKL+1,X
	EOR	ESTKL,X
	STA	ESTKL+1,X
	LDA	ESTKH+1,X
	EOR	ESTKH,X
	STA	ESTKH+1,X
	JMP	DROP
;*
;* SHIFT TOS-1 LEFT BY TOS
;*
SHL     STY     IPY
        LDA     ESTKL,X
        CMP     #$08
        BCC     +
        LDY     ESTKL+1,X
        STY     ESTKH+1,X
        LDY     #$00
        STY     ESTKL+1,X
        SBC     #$08
+	TAY
        BEQ     +
        LDA     ESTKL+1,X
-	ASL
        ROL     ESTKH+1,X
        DEY
        BNE     -
        STA     ESTKL+1,X
+	LDY     IPY
        JMP     DROP
;*
;* SHIFT TOS-1 RIGHT BY TOS
;*
SHR	STY	IPY
	LDA	ESTKL,X
	CMP	#$08
	BCC	++
	LDY	ESTKH+1,X
	STY	ESTKL+1,X
	CPY	#$80
	LDY	#$00
	BCC	+
	DEY
+	STY	ESTKH+1,X
	SEC
	SBC	#$08
++	TAY
	BEQ	+
	LDA	ESTKH+1,X
-	CMP	#$80
	ROR
	ROR	ESTKL+1,X
	DEY
	BNE	-
	STA	ESTKH+1,X
+	LDY	IPY
	JMP	DROP
;*
;* LOGICAL AND
;*
LAND 	LDA	ESTKL+1,X
	ORA	ESTKH+1,X
	BEQ	++
	LDA	ESTKL,X
	ORA	ESTKH,X
	BEQ	+
	LDA	#$FF
+	STA	ESTKL+1,X
	STA	ESTKH+1,X
++	JMP	DROP
;*
;* LOGICAL OR
;*
LOR 	LDA	ESTKL,X
	ORA	ESTKH,X
	ORA	ESTKL+1,X
	ORA	ESTKH+1,X
	BEQ	+
	LDA	#$FF
 	STA	ESTKL+1,X
	STA	ESTKH+1,X
+	JMP	DROP
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
;* LOGICAL NOT
;*
LNOT    LDA     ESTKL,X
        ORA     ESTKH,X
        BNE     +
        LDA     #$FF
        STA     ESTKL,X
        STA     ESTKH,X
        JMP     NEXTOP
;*
;* CONSTANT
;*
ZERO 	DEX
+	LDA	#$00
	STA	ESTKL,X
	STA	ESTKH,X
	JMP	NEXTOP
CFFB	DEX
	LDA	#$FF
	STA	ESTKH,X
        INY                     ;+INC_IP
	LDA	(IP),Y
	STA	ESTKL,X
	JMP	NEXTOP
CB	DEX
	LDA	#$00
	STA	ESTKH,X
        INY                     ;+INC_IP
	LDA	(IP),Y
	STA	ESTKL,X
	JMP	NEXTOP
;*
;* LOAD ADDRESS & LOAD CONSTANT WORD (SAME THING, WITH OR WITHOUT FIXUP)
;*
-       TYA                     ; RENORMALIZE IP
        CLC
        ADC     IPL
        STA     IPL
        BCC     +
        INC     IPH
+       LDY     #$FF
LA      INY                     ;+INC_IP
        BMI     -
        DEX
        LDA     (IP),Y
        STA     ESTKL,X
        INY
        LDA     (IP),Y
        STA     ESTKH,X
        JMP     NEXTOP
CW      DEX
        INY                     ;+INC_IP
        LDA     (IP),Y
        STA     ESTKL,X
        INY
        LDA     (IP),Y
        STA     ESTKH,X
        JMP     NEXTOP
;*
;* CONSTANT STRING
;*
CS	DEX
        ;INY                     ;+INC_IP
	TYA			; NORMALIZE IP AND SAVE STRING ADDR ON ESTK
	SEC
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
	LDA	(IP),Y		; SKIP TO NEXT OP ADDR AFTER STRING
	TAY
	JMP	NEXTOP
}
!IFDEF PLAS128 {
	LDA 	PPL	 	; SCAN POOL FOR STRING ALREADY THERE
	STA 	TMPL
	LDA	PPH
	STA	TMPH
_CMPPSX ;LDA	TMPH		; CHECK FOR END OF POOL
	CMP	IFPH
	BCC	_CMPSX		; CHECK FOR MATCHING STRING
	BNE	_CPYSX		; BEYOND END OF POOL, COPY STRING OVER
	LDA	TMPL
	CMP	IFPL
	BCS	_CPYSX		; AT OR BEYOND END OF POOL, COPY STRING OVER
_CMPSX	LDA	(TMP),Y		; COMPARE STRINGS FROM AUX MEM TO STRINGS IN MAIN MEM
	CMP	(IP),Y		; COMPARE STRING LENGTHS
	BNE	_CNXTSX1
	TAY
_CMPCSX LDA	(TMP),Y	 	; COMPARE STRING CHARS FROM END
	CMP	(IP),Y
	BNE	_CNXTSX
	DEY
	BNE	_CMPCSX
	LDA	TMPL		; MATCH - SAVE EXISTING ADDR ON ESTK AND MOVE ON
	STA	ESTKL,X
	LDA	TMPH
	STA	ESTKH,X
	BNE	_CEXSX
_CNXTSX LDY	#$00
	LDA	(TMP),Y
_CNXTSX1 SEC
	ADC	TMPL
	STA	TMPL
	LDA	#$00
	ADC	TMPH
	STA	TMPH
	BNE	_CMPPSX
_CPYSX	LDA	(IP),Y		; COPY STRING FROM AUX TO MAIN MEM POOL
	TAY			; MAKE ROOM IN POOL AND SAVE ADDR ON ESTK
	EOR	#$FF
	CLC
	ADC	PPL
	STA	PPL
	STA	ESTKL,X
	LDA	#$FF
	ADC	PPH
	STA	PPH
	+CHECKVSHEAPHIGHINA PP
	STA	ESTKH,X		; COPY STRING FROM AUX MEM BYTECODE TO MAIN MEM POOL
_CPYSX1 LDA	(IP),Y
	STA	(PP),Y
	DEY
	CPY	#$FF
	BNE	_CPYSX1
	INY
_CEXSX	LDA	(IP),Y		; SKIP TO NEXT OP ADDR AFTER STRING
	TAY
	JMP	NEXTOP
}
;*
;* LOAD VALUE FROM ADDRESS TAG
;*
LB      LDA     ESTKL,X
        STA     ESTKH-1,X
        LDA     (ESTKH-1,X)
        STA     ESTKL,X
        LDA     #$00
        STA     ESTKH,X
        JMP     NEXTOP
LW      LDA     ESTKL,X
        STA     ESTKH-1,X
        LDA     (ESTKH-1,X)
        STA     ESTKL,X
        INC     ESTKH-1,X
        BEQ     +
        LDA     (ESTKH-1,X)
        STA     ESTKH,X
        JMP     NEXTOP
+       INC     ESTKH,X
        LDA     (ESTKH-1,X)
        STA     ESTKH,X
        JMP     NEXTOP
;*
;* LOAD ADDRESS OF LOCAL FRAME OFFSET
;*
-       TYA                     ; RENORMALIZE IP
        CLC
        ADC     IPL
        STA     IPL
        BCC     +
        INC     IPH
+       LDY     #$FF
LLA     INY                     ;+INC_IP
        BMI     -
        LDA     (IP),Y
        DEX
        CLC
        ADC     IFPL
        STA     ESTKL,X
        LDA     #$00
        ADC     IFPH
        STA     ESTKH,X
        JMP     NEXTOP
;*
;* LOAD VALUE FROM LOCAL FRAME OFFSET
;*
LLB     INY                     ;+INC_IP
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
LLW     INY                     ;+INC_IP
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
!IF SELFMODIFY {
LAB     INY                     ;+INC_IP
	LDA	(IP),Y
	STA	LABLDA+1
        INY                     ;+INC_IP
	LDA	(IP),Y
	STA	LABLDA+2
LABLDA	LDA	$FFFF
	DEX
	STA	ESTKL,X
	LDA	#$00
	STA	ESTKH,X
	JMP	NEXTOP
} ELSE {
LAB     INY                     ;+INC_IP
        LDA     (IP),Y
        STA     ESTKH-2,X
        INY                     ;+INC_IP
        LDA     (IP),Y
        STA     ESTKH-1,X
        LDA     (ESTKH-2,X)
        DEX
        STA     ESTKL,X
        LDA     #$00
        STA     ESTKH,X
        JMP     NEXTOP
}
LAW     INY                     ;+INC_IP
        LDA     (IP),Y
        STA     TMPL
        INY                     ;+INC_IP
        LDA     (IP),Y
        STA     TMPH
        STY     IPY
        LDY     #$00
        LDA     (TMP),Y
        DEX
        STA     ESTKL,X
        INY
        LDA     (TMP),Y
        STA     ESTKH,X
        LDY     IPY
        JMP     NEXTOP
;*
;* STORE VALUE TO ADDRESS
;*
SB      LDA     ESTKL,X
        STA     ESTKH-1,X
        LDA     ESTKL+1,X
        STA     (ESTKH-1,X)
        INX
        JMP     DROP
SW      LDA     ESTKL,X
        STA     ESTKH-1,X
        LDA     ESTKL+1,X
        STA     (ESTKH-1,X)
        LDA     ESTKH+1,X
        INC     ESTKH-1,X
        BEQ     +
        STA     (ESTKH-1,X)
        INX
        JMP     DROP
+       INC     ESTKH,X
        STA     (ESTKH-1,X)
        INX
        JMP     DROP
;*
;* STORE VALUE TO LOCAL FRAME OFFSET
;*
SLB     INY                     ;+INC_IP
        LDA     (IP),Y
        STY     IPY
        TAY
        LDA     ESTKL,X
        STA     (IFP),Y
        LDY     IPY
        BMI     FIXDROP
        JMP     DROP
SLW     INY                     ;+INC_IP
        LDA     (IP),Y
        STY     IPY
        TAY
        LDA     ESTKL,X
        STA     (IFP),Y
        INY
        LDA     ESTKH,X
        STA     (IFP),Y
        LDY     IPY
        BMI     FIXDROP
        JMP     DROP
FIXDROP TYA
        LDY     #$00
        CLC
        ADC     IPL
        STA     IPL
        BCC     +
        INC     IPH
+       JMP     DROP
;*
;* STORE VALUE TO LOCAL FRAME OFFSET WITHOUT POPPING STACK
;*
DLB     INY                     ;+INC_IP
	LDA	(IP),Y
	STY	IPY
	TAY
	LDA	ESTKL,X
	STA	(IFP),Y
	LDY	IPY
	JMP	NEXTOP
DLW     INY                     ;+INC_IP
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
-       TYA                     ; RENORMALIZE IP
        CLC
        ADC     IPL
        STA     IPL
        BCC     +
        INC     IPH
+       LDY     #$FF
!IF SELFMODIFY {
SAB     INY                     ;+INC_IP
	BMI	-
	LDA	(IP),Y
	STA	SABSTA+1
        INY                     ;+INC_IP
	LDA	(IP),Y
	STA	SABSTA+2
	LDA	ESTKL,X
SABSTA	STA	$FFFF
	JMP	DROP
} ELSE {
SAB     INY                     ;+INC_IP
        BMI     -
        LDA     (IP),Y
        STA     ESTKH-2,X
        INY                     ;+INC_IP
        LDA     (IP),Y
        STA     ESTKH-1,X
        LDA     ESTKL,X
        STA     (ESTKH-2,X)
        JMP     DROP
}
SAW     INY                     ;+INC_IP
        LDA     (IP),Y
        STA     TMPL
        INY                     ;+INC_IP
        LDA     (IP),Y
        STA     TMPH
        STY     IPY
        LDY     #$00
        LDA     ESTKL,X
        STA     (TMP),Y
        INY
        LDA     ESTKH,X
        STA     (TMP),Y
        LDY     IPY
        BMI     +	; SFTODO: CAN I REJIG THE CODE SO THIS CAN BMI DIRECTLY TO FIXDROP WITHOUT AN INTERMEDIATE JMP?
        JMP     DROP
+	JMP	FIXDROP
;*
;* STORE VALUE TO ABSOLUTE ADDRESS WITHOUT POPPING STACK
;*
!IF SELFMODIFY {
DAB     INY                     ;+INC_IP
	LDA	(IP),Y
	STA	DABSTA+1
        INY                     ;+INC_IP
	LDA	(IP),Y
	STA	DABSTA+2
	LDA	ESTKL,X
DABSTA	STA	$FFFF
	JMP	NEXTOP
} ELSE {
DAB     INY                     ;+INC_IP
        LDA     (IP),Y
        STA     ESTKH-2,X
        INY                     ;+INC_IP
        LDA     (IP),Y
        STA     ESTKH-1,X
        LDA     ESTKL,X
        STA     (ESTKH-2,X)
        JMP     NEXTOP
}
DAW     INY                     ;+INC_IP
        LDA     (IP),Y
        STA     TMPL
        INY                     ;+INC_IP
        LDA     (IP),Y
        STA     TMPH
        STY     IPY
        LDY     #$00
        LDA     ESTKL,X
        STA     (TMP),Y
        INY
        LDA     ESTKH,X
        STA     (TMP),Y
        LDY     IPY
        JMP     NEXTOP
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
	STA	ESTKL+1,X
	STA	ESTKH+1,X
	JMP	DROP
;
ISNE	LDA	ESTKL,X
	CMP	ESTKL+1,X
	BNE	ISTRU
	LDA	ESTKH,X
	CMP	ESTKH+1,X
	BNE	ISTRU
ISFLS 	LDA	#$00
	STA	ESTKL+1,X
	STA	ESTKH+1,X
	JMP	DROP
;
ISGE    LDA     ESTKL+1,X
        CMP     ESTKL,X
        LDA     ESTKH+1,X
        SBC     ESTKH,X
        BVS     +
        BPL     ISTRU
        BMI     ISFLS
+       BPL     ISFLS
        BMI     ISTRU
;
ISGT    LDA     ESTKL,X
        CMP     ESTKL+1,X
        LDA     ESTKH,X
        SBC     ESTKH+1,X
        BVS     +
        BMI     ISTRU
        BPL     ISFLS
+       BMI     ISFLS
        BPL     ISTRU
;
ISLE    LDA     ESTKL,X
        CMP     ESTKL+1,X
        LDA     ESTKH,X
        SBC     ESTKH+1,X
        BVS     +
        BPL     ISTRU
        BMI     ISFLS
+       BPL     ISFLS
        BMI     ISTRU
;
ISLT    LDA     ESTKL+1,X
        CMP     ESTKL,X
        LDA     ESTKH+1,X
        SBC     ESTKH,X
        BVS     +
        BMI     ISTRU
        BPL     ISFLS
+       BMI     ISFLS
        BPL     ISTRU
;*
;* BRANCHES
;*
BRTRU   INX
        LDA     ESTKH-1,X
        ORA     ESTKL-1,X
        BNE     BRNCH
NOBRNCH INY                     ;+INC_IP
        INY
        BMI     FIXNEXT
        JMP     NEXTOP
FIXNEXT TYA
        LDY     #$00
        CLC
        ADC     IPL
        STA     IPL
        BCC     +
        INC     IPH
+       JMP     NEXTOP
BRFLS   INX
        LDA     ESTKH-1,X
        ORA     ESTKL-1,X
        BNE     NOBRNCH
BRNCH   TYA                     ; FLATTEN IP
        SEC
        ADC     IPL
        STA     TMPL
        LDA     #$00
        TAY
        ADC     IPH
        STA     TMPH            ; ADD BRANCH OFFSET
        LDA     (TMP),Y
        ;CLC                    ; BETTER NOT CARRY OUT OF IP+Y
        ADC     TMPL
        STA     IPL
        INY
        LDA     (TMP),Y
        ADC     TMPH
        STA     IPH
        DEY
        JMP     FETCHOP
BREQ    INX
        LDA     ESTKL-1,X
        CMP     ESTKL,X
        BNE     NOBRNCH
        LDA     ESTKH-1,X
        CMP     ESTKH,X
        BEQ     BRNCH
        BNE     NOBRNCH
BRNE    INX
        LDA     ESTKL-1,X
        CMP     ESTKL,X
        BNE     BRNCH
        LDA     ESTKH-1,X
        CMP     ESTKH,X
        BEQ     NOBRNCH
        BNE     BRNCH
BRGT    INX
        LDA     ESTKL-1,X
        CMP     ESTKL,X
        LDA     ESTKH-1,X
        SBC     ESTKH,X
        BVS     +
        BPL     NOBRNCH
        BMI     BRNCH
+       BPL     BRNCH
        BMI     NOBRNCH
BRLT    INX
        LDA     ESTKL,X
        CMP     ESTKL-1,X
        LDA     ESTKH,X
        SBC     ESTKH-1,X
        BVS     +
        BPL     NOBRNCH
        BMI     BRNCH
+       BPL     BRNCH
        BMI     NOBRNCH
IBRNCH  TYA                     ; FLATTEN IP
        CLC
        ADC     IPL
        STA     TMPL
        LDA     #$00
        TAY
        ADC     IPH
        STA     TMPH            ; ADD BRANCH OFFSET
        LDA     TMPL
        ;CLC                    ; BETTER NOT CARRY OUT OF IP+Y
        ADC     ESTKL,X
        STA     IPL
        LDA     TMPH
        ADC     ESTKH,X
        STA     IPH
        JMP     DROP
;*
;* CALL INTO ABSOLUTE ADDRESS (NATIVE CODE)
;*
CALL    INY                     ;+INC_IP
	LDA	(IP),Y
	STA	TMPL
        INY                     ;+INC_IP
	LDA	(IP),Y
	STA	TMPH
	TYA
	CLC
	ADC	IPL
	PHA
	LDA	IPH
	ADC	#$00
	PHA
!IFDEF PLAS128 {
	LDA	$F4
	PHA
}
	JSR	JMPTMP     ; PLAS128: may page in another bank
!IFDEF PLAS128 {
	PLA
	STA	$F4
	STA	$FE30
}
!IF CHECKEXPRESSIONSTACK {
	CPX	#(ESTKSZ/2)+1
	BCS	ESTKERR
}
	PLA
	STA	IPH
	PLA
	STA	IPL
	LDY	#$01
	JMP	FETCHOP
!IF CHECKEXPRESSIONSTACK {
ESTKERR
	BRK
	!BYTE	$01
	;* This isn't the most descriptive error, but it could be an overflow
	;* or an underflow and we don't want to waste too much space on a long
	;* message.
	!TEXT	"Stack"
	BRK
}
;*
;* INDIRECT CALL TO ADDRESS (NATIVE CODE)
;*
;* SFTODO: Could I save code by doing a JMP into the CALL implementation after setting
;* up TMPL/TMPH? I don't think ICAL is very common so not too worried about the minor
;* performance impact.
ICAL 	LDA	ESTKL,X
	STA	TMPL
	LDA	ESTKH,X
	STA	TMPH
	INX
	TYA
	CLC
	ADC	IPL
	PHA
	LDA	IPH
	ADC	#$00
	PHA
!IFDEF PLAS128 {
	LDA	$F4
	PHA
}
ICALADR	JSR	JMPTMP	     ; PLAS128: may page in another bank
!IFDEF PLAS128 {
	PLA
	STA	$F4
	STA	$FE30
}
;* We could do CHECKEXPRESSIONSTACK here, but ICAL isn't that common and the
;* expression stack checking is never going to catch everything (that would
;* require every DEX opcode to check) so it's probably not worth bloating the
;* VM further.
	PLA
	STA	IPH
	PLA
	STA	IPL
	LDY	#$01
	JMP	FETCHOP
;*
;* JUMP INDIRECT THROUGH TMP
;*
JMPTMP	JMP	(TMP)
;*
;* ENTER FUNCTION WITH FRAME SIZE AND PARAM COUNT
;*
ENTER	
!IFDEF PLAS128 {
;* We save IFP as a delta from PP so that the CPU stack doesn't contain
;* absolute addresses in the parameter stack; this is important to allow 
;* mode changes to work (they move the parameter stack).
	SEC			; SAVE ON STACK FOR LEAVE
	LDA	IFPL
	SBC	PPL
	PHA
	LDA	IFPH
	SBC	PPH
	PHA
}
	INY
	LDA	(IP),Y
	EOR	#$FF		; ALLOCATE FRAME
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
	+CHECKVSHEAP IFP
}
!IFDEF PLAS128 {
	LDA	#$FF
	ADC	PPH
	STA	PPH
	STA	IFPH
	+CHECKVSHEAPHIGHINA IFP
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
+	LDY	#$03
!IF CHECKEXPRESSIONSTACK {
	CPX	#(ESTKSZ/2)+1
	BCS	ESTKERR
}
	JMP	FETCHOP
;*
;* LEAVE FUNCTION
;*
LEAVE   INY                     ;+INC_IP
        LDA     (IP),Y
	CLC
	ADC	IFPL
!IFDEF PLAS128 {
	STA	PPL
	LDA	#$00
	ADC	IFPH
	STA	PPH
	CLC			; RESTORE PREVIOUS FRAME
	PLA
	ADC	PPH
	STA	IFPH
	CLC
	PLA
	ADC	PPL
	STA	IFPL
	BCC	+
	INC	IFPH
RET
+	RTS
}
!IFNDEF PLAS128 {
	STA	IFPL
	BCS	+
	RTS
+	INC	IFPH
RET	RTS
}
; Compiled PLASMA code
A1CMD	