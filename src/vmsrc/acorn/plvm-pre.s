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
DVSIGN	=	ESP
DROP    =       ZPCODE
NEXTOP  =       DROP+1
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
	!SOURCE "vmsrc/acorn/vmconstants.inc"
;* Assert this here; we can't do it in cmd.pla where it most logically belongs
;* or in plvmzp.inc because that has to be translatable by acmetoplasma.py. We
;* have this constraint because parsemodname() uses SCRATCH to return the
;* module name as a PLASMA string (hence the +1).
!IF SCRATCHSZ < MAXNAMELEN+1 {
    !ERROR "SCRATCHSZ too small"
}

	;* Note this doesn't preserve A!
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

	;* Note this doesn't preserve A!
	!MACRO	CHECKVSHEAP .P {
		!IF CHECKPARAMETERSTACK {
			LDA	.P+1
			+CHECKVSHEAPHIGHINA .P
		}
	}

	;* On PLAS128 JIT builds, CALL/ICAL/RET need to page in the RAM bank containing
	;* the JITted machine code. Interpreted functions have the bank containing their
	;* bytecode pages in by IINTERP, which lives in main RAM, but JITted functions
	;* are entered directly at their address in sideways RAM, so we must have the
	;* correct bank paged in in case a CALL/ICAL is to JITted code. RET needs to
	;* page in the RAM bank to handle the case where JITted code is calling an
	;* interpreted function; the interpreted function's IINTERP will have paged in
	;* the bank containing its bytecode so we need to undo that. We will end up
	;* paging in the JIT bank more often than we need to, but I don't think it can
	;* be helped, and the paging only happens on interpreted function entry/exit
	;* so it shouldn't be too much of a drag on performance.
	!MACRO	SELECTJITBANK {
		!IFDEF PLAS128 {
		    !IFDEF JIT {
			LDA	RAMBANK+0   ; JITted code always lives in our first bank
			STA	$F4
			STA	$FE30
		    }
		}
	}
;*
;* INTERPRETER HEADER+INITIALIZATION
;*
	*=	START
SEGBEGIN JMP	VMINIT
;* When we relocate the code, we don't relocate the JMP VMINIT at SEGBEGIN; this is why we
;* pass an ignored_bytes argument of 3 to add-relocations.py. We do this because by setting
;* START to $XXFD, we are able to have RELOCSTART at $(XX+1)00, i.e. exactly on a page
;* boundary, which means we can place OPTBL there and satisfy its alignment requirements
;* without any fiddling or wasting any memory on padding.
RELOCSTART
;*
;* OPCODE TABLE
;*
!IF <* <> 0 {
	!ERROR "OPTBL must be page-aligned"
}
	!ALIGN	255,0
OPTBL   !WORD   CN,CN,CN,CN,CN,CN,CN,CN                                 ; 00 02 04 06 08 0A 0C 0E
        !WORD   CN,CN,CN,CN,CN,CN,CN,CN                                 ; 10 12 14 16 18 1A 1C 1E
        !WORD   MINUS1,BREQ,BRNE,LA,LLA,CB,CW,CS                        ; 20 22 24 26 28 2A 2C 2E
        !WORD   DROP,DROP2,DUP,DIVMOD,ADDI,SUBI,ANDI,ORI                ; 30 32 34 36 38 3A 3C 3E
        !WORD   ISEQ,ISNE,ISGT,ISLT,ISGE,ISLE,BRFLS,BRTRU               ; 40 42 44 46 48 4A 4C 4E
        !WORD   BRNCH,SEL,CALL,ICAL,ENTER,LEAVE,RET,CFFB                ; 50 52 54 56 58 5A 5C 5E
        !WORD   LB,LW,LLB,LLW,LAB,LAW,DLB,DLW                           ; 60 62 64 66 68 6A 6C 6E
        !WORD   SB,SW,SLB,SLW,SAB,SAW,DAB,DAW                           ; 70 72 74 76 78 7A 7C 7E
        !WORD   LNOT,ADD,SUB,MUL,DIV,MOD,INCR,DECR                      ; 80 82 84 86 88 8A 8C 8E
        !WORD   NEG,COMP,BAND,IOR,XOR,SHL,SHR,IDXW                      ; 90 92 94 96 98 9A 9C 9E
        !WORD   BRGT,BRLT,INCBRLE,ADDBRLE,DECBRGE,SUBBRGE,BRAND,BROR    ; A0 A2 A4 A6 A8 AA AC AE
        !WORD   ADDLB,ADDLW,ADDAB,ADDAW,IDXLB,IDXLW,IDXAB,IDXAW         ; B0 B2 B4 B6 B8 BA BC BE
	!WORD	NATV							; C0

; SFTODO: I reordered the opcodes compared to Apple code in order to avoid wasting the alignment padding for OPTBL; now OPTBL has been moved, it might be worth reordering the code again so it's more like the Apple for ease of comparison in future.
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
+       DEX
        LDA     TMPL            ; REMNDRL
        STA     ESTKL,X
        LDA     TMPH            ; REMNDRH
        STA     ESTKH,X
        ASL     DVSIGN          ; REMAINDER IS SIGN OF DIVIDEND
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
ANRTS	RTS
_DIV    STY     IPY
        LDY     #$11            ; #BITS+1
        LDA     #$00
        STA     TMPL            ; REMNDRL
        STA     TMPH            ; REMNDRH
        STA     DVSIGN
        LDA     ESTKH+1,X
        BPL     +
        INX
        JSR     _NEG
        DEX
        LDA     #$81
        STA     DVSIGN
+       ORA     ESTKL+1,X         ; DVDNDL
        BEQ     _DIVEX
        LDA     ESTKH,X
        BPL     _DIV1
        JSR     _NEG
        INC     DVSIGN
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
IINTERP2
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
!IFDEF JIT {
;*
;* JIT PROFILING ENTRY INTO INTERPRETER
;*
JITIINTERP
        PLA
        STA     TMPL
        PLA
        STA     TMPH
        LDY     #$03
        LDA     (TMP),Y         ; DEC JIT COUNT
!IFNDEF PLAS128 {
	; PLASJIT only runs on a second processor, so we can use CMOS opcodes here.
	; A bit of a pointless micro-optimisations really.
	!CPU	65C02
	DEC
	!CPU	6502
} ELSE {
        SEC
        SBC     #$01
}
        STA     (TMP),Y
	BNE	IINTERP2	; INTERP BYTECODE AS USUAL
RUNJIT  LDA	TMPL
	SEC
	SBC	#$02		; POINT TO DEF ENTRY
	STA	TMPL
	BCS	+
	DEC	TMPH
+	DEX                     ; ADD PARAMETER TO DEF ENTRY
        LDA     TMPL
        PHA                     ; AND SAVE IT FOR LATER
        STA     ESTKL,X
        LDA     TMPH
        PHA
        STA     ESTKH,X
        JSR	JMPJITCOMP	; CALL JIT COMPILER
        PLA
        STA     TMPH
        PLA
        STA     TMPL
        JMP     (TMP)           ; RE-CALL ORIGINAL DEF ENTRY
JMPJITCOMP
	JMP 	(JITCOMP)
}
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
;* DUPLICATE TOS
;*
DUP 	DEX
	LDA	ESTKL+1,X
	STA	ESTKL,X
	LDA	ESTKH+1,X
	STA	ESTKH,X
	JMP	NEXTOP
;*
;* ADD IMMEDIATE TO TOS
;*
ADDI    INY                     ;+INC_IP
        LDA     (IP),Y
        CLC
        ADC     ESTKL,X
        STA     ESTKL,X
        BCC     +
        INC     ESTKH,X
+       JMP     NEXTOP
;*
;* SUB IMMEDIATE FROM TOS
;*
SUBI    INY                     ;+INC_IP
        LDA     ESTKL,X
        SEC
        SBC     (IP),Y
        STA     ESTKL,X
        BCS     +
        DEC     ESTKH,X
+       JMP     NEXTOP
;*
;* AND IMMEDIATE TO TOS
;*
ANDI    INY                     ;+INC_IP
        LDA     (IP),Y
        AND     ESTKL,X
        STA     ESTKL,X
        LDA     #$00
        STA     ESTKH,X
        JMP     NEXTOP
;*
;* IOR IMMEDIATE TO TOS
;*
ORI     INY                     ;+INC_IP
        LDA     (IP),Y
        ORA     ESTKL,X
        STA     ESTKL,X
        JMP     NEXTOP
;*
;* LOGICAL NOT
;*
LNOT    LDA     ESTKL,X
        ORA     ESTKH,X
        BEQ     +
        LDA     #$00
        STA     ESTKL,X
        STA     ESTKH,X
        JMP     NEXTOP
;*
;* CONSTANT -1, NYBBLE, BYTE, $FF BYTE, WORD (BELOW)
;*
MINUS1  DEX
+       LDA     #$FF
        STA     ESTKL,X
        STA     ESTKH,X
        JMP     NEXTOP
CN      DEX
        LSR                     ; A = CONST * 2
        STA     ESTKL,X
        LDA     #$00
        STA     ESTKH,X
        JMP     NEXTOP
CB      DEX
        LDA     #$00
        STA     ESTKH,X
        INY                     ;+INC_IP
        LDA     (IP),Y
        STA     ESTKL,X
        JMP     NEXTOP
CFFB    DEX
        LDA     #$FF
        STA     ESTKH,X
        INY                     ;+INC_IP
        LDA     (IP),Y
        STA     ESTKL,X
        JMP     NEXTOP
;*
;* LOAD ADDRESS & LOAD CONSTANT WORD (SAME THING, WITH OR WITHOUT FIXUP)
;*
;* LA and CW differ only in that LA does RENORMALIZE IP; we could share their implementation
;* if we were willing to do or not do RENORMALIZE IP for both, but it seems safest to do as
;* the Apple Vm does. We'd save 16 bytes by making CW an alias for LA, so it's not a huge
;* cost.
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
	STA	ESTKH,X
	+CHECKVSHEAPHIGHINA PP
_CPYSX1 LDA	(IP),Y		; COPY STRING FROM AUX MEM BYTECODE TO MAIN MEM POOL
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
;* ADD VALUE FROM LOCAL FRAME OFFSET
;*
ADDLB   INY                     ;+INC_IP
        LDA     (IP),Y
        STY     IPY
        TAY
        LDA     (IFP),Y
        CLC
        ADC     ESTKL,X
        STA     ESTKL,X
        BCC     +
        INC     ESTKH,X
+       LDY     IPY
        JMP     NEXTOP
ADDLW   INY                     ;+INC_IP
        LDA     (IP),Y
        STY     IPY
        TAY
        LDA     (IFP),Y
        CLC
        ADC     ESTKL,X
        STA     ESTKL,X
        INY
        LDA     (IFP),Y
        ADC     ESTKH,X
        STA     ESTKH,X
        LDY     IPY
        JMP     NEXTOP
;*
;* INDEX VALUE FROM LOCAL FRAME OFFSET
;*
IDXLB   INY                     ;+INC_IP
        LDA     (IP),Y
        STY     IPY
        TAY
        LDA     (IFP),Y
        LDY     #$00
        ASL
        BCC     +
        INY
        CLC
+       ADC     ESTKL,X
        STA     ESTKL,X
        TYA
        ADC     ESTKH,X
        STA     ESTKH,X
        LDY     IPY
        JMP     NEXTOP
IDXLW   INY                     ;+INC_IP
        LDA     (IP),Y
        STY     IPY
        TAY
        LDA     (IFP),Y
        ASL
        STA     TMPL
        INY
        LDA     (IFP),Y
        ROL
        STA     TMPH
        LDA     TMPL
        CLC
        ADC     ESTKL,X
        STA     ESTKL,X
        LDA     TMPH
        ADC     ESTKH,X
        STA     ESTKH,X
        LDY     IPY
        JMP     NEXTOP
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
;* ADD VALUE FROM ABSOLUTE ADDRESS
;*
ADDAB   INY                     ;+INC_IP
        LDA     (IP),Y
        STA     ESTKH-2,X
        INY                     ;+INC_IP
        LDA     (IP),Y
        STA     ESTKH-1,X
        LDA     (ESTKH-2,X)
        CLC
        ADC     ESTKL,X
        STA     ESTKL,X
        BCC     +
        INC     ESTKH,X
+       JMP     NEXTOP
ADDAW   INY                     ;+INC_IP
        LDA     (IP),Y
        STA     SRCL
        INY                     ;+INC_IP
        LDA     (IP),Y
        STA     SRCH
        STY     IPY
        LDY     #$00
        LDA     (SRC),Y
        CLC
        ADC     ESTKL,X
        STA     ESTKL,X
        INY
        LDA     (SRC),Y
        ADC     ESTKH,X
        STA     ESTKH,X
        LDY     IPY
        JMP     NEXTOP
;*
;* INDEX VALUE FROM ABSOLUTE ADDRESS
;*
IDXAB   INY                     ;+INC_IP
        LDA     (IP),Y
        STA     ESTKH-2,X
        INY                     ;+INC_IP
        LDA     (IP),Y
        STA     ESTKH-1,X
        LDA     (ESTKH-2,X)
        STY     IPY
        LDY     #$00
        ASL
        BCC     +
        INY
        CLC
+       ADC     ESTKL,X
        STA     ESTKL,X
        TYA
        ADC     ESTKH,X
        STA     ESTKH,X
        LDY     IPY
        JMP     NEXTOP
IDXAW   INY                     ;+INC_IP
        LDA     (IP),Y
        STA     SRCL
        INY                     ;+INC_IP
        LDA     (IP),Y
        STA     SRCH
        STY     IPY
        LDY     #$00
        LDA     (SRC),Y
        ASL
        STA     TMPL
        INY
        LDA     (SRC),Y
        ROL
        STA     TMPH
        LDA     TMPL
        CLC
        ADC     ESTKL,X
        STA     ESTKL,X
        LDA     TMPH
        ADC     ESTKH,X
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
;*
;* DROP TOS, TOS-1
;*
DROP2   INX
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
	LDA	#$00
	STA	ESTKH,X
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
        BMI     FIXDROP
        JMP     DROP
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
	LDA	#$00
	STA	ESTKH,X
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
	LDA	#$00
	STA	ESTKH,X
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
ISGE    LDA     ESTKL+1,X
        CMP     ESTKL,X
        LDA     ESTKH+1,X
        SBC     ESTKH,X
        BVS     +
        BPL     ISTRU
        BMI     ISFLS
+
-       BPL     ISFLS
        BMI     ISTRU
ISLE    LDA     ESTKL,X
        CMP     ESTKL+1,X
        LDA     ESTKH,X
        SBC     ESTKH+1,X
        BVS     -
        BPL     ISTRU
        BMI     ISFLS
ISGT    LDA     ESTKL,X
        CMP     ESTKL+1,X
        LDA     ESTKH,X
        SBC     ESTKH+1,X
        BVS     +
        BMI     ISTRU
        BPL     ISFLS
+
-       BMI     ISFLS
        BPL     ISTRU
ISLT    LDA     ESTKL+1,X
        CMP     ESTKL,X
        LDA     ESTKH+1,X
        SBC     ESTKH,X
        BVS     -
        BMI     ISTRU
        BPL     ISFLS
;
;*
;* BRANCHES
;*
SEL     INX
        TYA                     ; FLATTEN IP
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
        LDA     (IP),Y
        STA     TMPL            ; CASE COUNT
        INC     IPL
        BNE     CASELP
        INC     IPH
CASELP  LDA     ESTKL-1,X
        CMP     (IP),Y
        BEQ     +
        LDA     ESTKH-1,X
        INY
        SBC     (IP),Y
        BMI     CASEEND
-       INY
        INY
        DEC     TMPL
        BEQ     FIXNEXT
        INY
        BNE     CASELP
        INC     IPH
        BNE     CASELP
+       LDA     ESTKH-1,X
        INY
        SBC     (IP),Y
        BEQ     BRNCH
        BPL     -
CASEEND LDA     #$00
        STA     TMPH
        DEC     TMPL
        LDA     TMPL
        ASL                 ; SKIP REMAINING CASES
        ROL     TMPH
        ASL
        ROL     TMPH
;       CLC
        ADC     IPL
        STA     IPL
        LDA     TMPH
        ADC     IPH
        STA     IPH
        INY
        INY
FIXNEXT TYA
        LDY     #$00
        SEC
        ADC     IPL
        STA     IPL
        BCC     +
        INC     IPH
+       JMP     FETCHOP
BRAND   LDA     ESTKL,X
        ORA     ESTKH,X
        BEQ     BRNCH
        INX                     ; DROP LEFT HALF OF AND
        BNE     NOBRNCH
BROR    LDA     ESTKL,X
        ORA     ESTKH,X
        BNE     BRNCH
        INX                     ; DROP LEFT HALF OF OR
        BNE     NOBRNCH
BREQ    INX
        INX
        LDA     ESTKL-2,X
        CMP     ESTKL-1,X
        BNE     NOBRNCH
        LDA     ESTKH-2,X
        CMP     ESTKH-1,X
        BEQ     BRNCH
        BNE     NOBRNCH
BRNE    INX
        INX
        LDA     ESTKL-2,X
        CMP     ESTKL-1,X
        BNE     BRNCH
        LDA     ESTKH-2,X
        CMP     ESTKH-1,X
        BNE     BRNCH
        BEQ     NOBRNCH
BRTRU   INX
        LDA     ESTKH-1,X
        ORA     ESTKL-1,X
        BNE     BRNCH
NOBRNCH INY                     ;+INC_IP
        INY
        BMI     FIXNEXT
        JMP     NEXTOP
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
;*
;* FOR LOOPS PUT TERMINAL VALUE AT ESTK+1 AND CURRENT COUNT ON ESTK
;*
BRGT    LDA     ESTKL+1,X
        CMP     ESTKL,X
        LDA     ESTKH+1,X
        SBC     ESTKH,X
        BVS     +
        BPL     NOBRNCH
	BMI     BRNCH
BRLT    LDA     ESTKL,X
        CMP     ESTKL+1,X
        LDA     ESTKH,X
        SBC     ESTKH+1,X
        BVS     +
        BPL     NOBRNCH
        BMI     BRNCH
+       BMI     NOBRNCH
        BPL     BRNCH
DECBRGE DEC     ESTKL,X
        LDA     ESTKL,X
        CMP     #$FF
        BNE     +
        DEC     ESTKH,X
_BRGE   LDA     ESTKL,X
+       CMP     ESTKL+1,X
        LDA     ESTKH,X
        SBC     ESTKH+1,X
        BVS     +
        BPL     BRNCH
        BMI     NOBRNCH
INCBRLE INC     ESTKL,X
        BNE     _BRLE
        INC     ESTKH,X
_BRLE   LDA     ESTKL+1,X
        CMP     ESTKL,X
        LDA     ESTKH+1,X
        SBC     ESTKH,X
        BVS     +
        BPL     BRNCH
        BMI     NOBRNCH
+       BMI     BRNCH
        BPL     NOBRNCH
SUBBRGE LDA     ESTKL+1,X
        SEC
        SBC     ESTKL,X
        STA     ESTKL+1,X
        LDA     ESTKH+1,X
        SBC     ESTKH,X
        STA     ESTKH+1,X
        INX
        BNE     _BRGE
ADDBRLE LDA     ESTKL,X
        CLC
        ADC     ESTKL+1,X
        STA     ESTKL+1,X
        LDA     ESTKH,X
        ADC     ESTKH+1,X
        STA     ESTKH+1,X
        INX
        BNE     _BRLE
;*
;* CALL INTO ABSOLUTE ADDRESS (NATIVE CODE)
;*
CALL    INY                     ;+INC_IP
	LDA	(IP),Y
	STA	TMPL
        INY                     ;+INC_IP
	LDA	(IP),Y
	STA	TMPH
CALLCOM	TYA
	SEC
	ADC	IPL
	PHA
	LDA	IPH
	ADC	#$00
	PHA
!IFDEF PLAS128 {
	LDA	$F4
	PHA
	+SELECTJITBANK
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
	LDY	#$00
	JMP	FETCHOP
!IF CHECKEXPRESSIONSTACK {
ESTKERR
	BRK
	!BYTE	ERRSTACK
	;* This isn't the most descriptive error, but it could be an overflow
	;* or an underflow and we don't want to waste too much space on a long
	;* message.
	!TEXT	"Stack"
	BRK
}
;*
;* INDIRECT CALL TO ADDRESS (NATIVE CODE)
;*
ICAL 	LDA	ESTKL,X
	STA	TMPL
	LDA	ESTKH,X
	STA	TMPH
	INX
	BNE	CALLCOM		; ALWAYS BRANCHES
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
+	+SELECTJITBANK
	RTS
}
!IFNDEF PLAS128 {
	STA	IFPL
	BCS	+
	RTS
+	INC	IFPH
RET	RTS
}
;*
;* RETURN TO NATIVE CODE
;*
NATV    TYA                     ; FLATTEN IP
        SEC
        ADC     IPL
        STA     IPL
        BCS     +
        JMP     (IP)
+       INC     IPH
        JMP     (IP)
;*
;* BRK HANDLER
;*
BRKHND
	LDY	#0
	LDA	(error_message_ptr),Y
	STA	ERRNUM
	;* Note that as we only have ERRSTRSZ(=255) bytes for ERRSTR and we
	;* need one byte for the length, we must truncate error messages to
	;* no more than 254 characters. Y is the 1-based index into the error
	;* message in the following loop.
ERRCPY	INY
	CPY	#ERRSTRSZ
	BEQ	ERRCPD
	LDA	(error_message_ptr),Y
	BEQ	ERRCPD
	STA	ERRSTR,Y
	BNE	ERRCPY
ERRCPD	DEY
	STY	ERRSTR
	;* ERRNUM now holds the error number
	;* ERRSTR now holds the error message as a standard PLASMA string
	
	LDX	#$FF
	TXS
	;* We reset X (ESP) so the error handler has the full expression
	;* stack available - at the point the error occurred, it might
	;* have been (nearly) full and so any expression stack use in
	;* the error handler would trample on memory outside the stack if
	;* we left it alone. This will trample on any values which were
	;* pushed onto the expression stack before the call to setjmp()
	;* and which might be expected to be there after setjmp() returns
	;* via longjmp(). This is OK because longjmp() will restore X and
	;* the expression stack from the jmp_buf. (We could partially
	;* avoid the need for this by just saving X (ESP) in jmp_buf,
	;* but not the expression stack itself, and setting X=2 here so
	;* the error handlers runs with a tiny expression stack, just
	;* enough to call longjmp(). We'd make setjmp() fail if X<=2 on
	;* entry. This wouldn't be a perfect solution as the expression stack
	;* could shrink after the setjmp() and before the longjmp(),
	;* so important state could still be lost; setjmp.pla is an
	;* example of this. The expression stack plays the same role as
	;* registers, and really it needs to be restored by longjmp(),
	;* so we do that.)
	LDX	#ESTKSZ/2	; INIT EVAL STACK INDEX
	JSR	BRKJMP
	;* We do not expect control to ever return from *ERRFP, and if
	;* does we can't do anything useful - we can't generate an error,
	;* as it would just end up back here. We could potentially try
	;* to re-enter the current language, but that's not particularly
	;* helpful, so we just print '!' and hang. This really should
	;* never happen - the default error_handler() function used for
	;* ERRFP does a longjmp(), so if that doesn't work either the
	;* VM is totally hosed or the user is playing around with ERRFP
	;* and has to suffer the consequences of getting it wrong. :-)
	;* It's also desirable not to waste space in the VM on code for
	;* this 'impossible' case.
	;* TODO: Could/should we therefore replace the JSR BRKJMP above
	;* with a simple JMP (ERRFP)?
	LDA	#'!'
	JSR	OSWRCH
BRKLP	JMP	BRKLP
BRKJMP	JMP	(ERRFP)
; Compiled PLASMA code
A1CMD	
