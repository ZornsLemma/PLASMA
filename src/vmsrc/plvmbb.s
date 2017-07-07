;**********************************************************
;*
;*            BBC PLASMA INTERPETER
;*
;*             SYSTEM ROUTINES AND LOCATIONS
;*
;**********************************************************

;* If this is defined, code is included when lowering IFP/PP
;* to ensure they don't drop below the top of the heap. This
;* is fairly cheap; the fncall benchmark slows down by <2%
;* and ENTER is the main opcode penalised by this checking, so
;* most code should see even less cost. (CS is also penalised,
;* but only when the string isn't already in the pool, and it's
;* relatively slow anyway.)
CHECKPARAMETERSTACK = 1

BBC = 1

;*
;* VM ZERO PAGE LOCATIONS
;*
	!SOURCE	"vmsrc/plvmzp.inc"
;*
;* ACORN OS AND VM CONSTANTS
;*
	!SOURCE "vmsrc/acornc.inc"
;*
;* INTERPRETER INSTRUCTION POINTER INCREMENT MACRO
;*
	!MACRO	INC_IP	{
	INY
	BNE	*+4
	INC	IPH
	}

	!MACRO	CHECKVSHEAPHIGHINA .P {
		!IFDEF CHECKPARAMETERSTACK {
			CMP	HEAPH
			BEQ	.CHECKLOW
			BCS	.OK
.FAIL
			JMP HITHEAP
.CHECKLOW
			LDA	.P
			CMP	HEAPL
			BCC	.FAIL
.OK
		}
	}

	!MACRO	CHECKVSHEAP .P {
		!IFDEF CHECKPARAMETERSTACK {
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
	!BYTE $00		; same error number as BASIC "No room"
	!TEXT "No room"
	BRK

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
;* We save IFP as a delta from PP so that the CPU stack doesn't contain
;* absolute addresses in the parameter stack; this is important to allow 
;* mode changes to work (they move the parameter stack).
	SEC			; SAVE ON STACK FOR LEAVE RET
	LDA	IFPL
	SBC	PPL
	PHA
	LDA	IFPH
	SBC	PPH
	PHA
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
	; This code must be kept consistent with memxcpy()

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
;* See comments in INTERP about why we store IFP like this
	SEC			; SAVE ON STACK FOR LEAVE RET
	LDA	IFPL
	SBC	PPL
	PHA
	LDA	IFPH
	SBC	PPH
	PHA
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
	LDA	(IP),Y		; SKIP TO NEXT OP ADDR AFTER STRING
	TAY
	JMP	NEXTOP
}
!IFDEF PLAS128 {
	POOLSIZE = 16*2 ; 2 byte entries
	HASHMASK = $1E ; %00011110

	HEADPTR = SRC
	THISPTR = DST

	; To avoid problems where the CS opcode is used inside a loop and
	; chews up all the memory, we create a per-function-call string pool
	; on the frame stack. The address of the CS opcode (actually the
	; byte immediately after it) provides a unique key which identifies
	; the string within the function so we can avoid comparing the
	; actual strings. (This means of course that two CS opcodes with
	; the same string will create two entries in the string pool, but
	; this is still better than the naive approach used earlier, and
	; I think the extra performance of this is worth it.)
	;
	; Just below IFP is a POOLSIZE-byte hash table;
	; each entry is a pointer to the first element of a linked list
	; of entries for that hash key. Each linked list element has the
	; following structure:
	; offset 0 - IP value (2 bytes)
	; offset 2 - pointer to next entry (2 bytes)
	; offset 4 - string

	; Remember that we have normalised IP, so Y=0, (IP),Y addresses
	; the byte after the CS opcode. We therefore don't need to save Y
	; or factor it into the hash lookup.

	; If this is the first allocation in this stack frame (i.e. PP=IFP)
	; we need to create a hash table.
	LDA	PPL
	CMP	IFPL
	BNE	HAVEPOOL
	LDA	PPH
	CMP	IFPH
	BNE	HAVEPOOL
	; We need to create a hash table. Lower PP to create space for it.
	SEC
	LDA	IFPL
	SBC	#POOLSIZE
	STA	PPL
	LDA	IFPH
	SBC	#0
	STA	PPH
	+CHECKVSHEAPHIGHINA PP
	; Now zero the hash table.
	LDY	#POOLSIZE-1
	LDA	#0
-	STA	(PP),Y
	DEY
	BPL	-

HAVEPOOL
	; OK, we have a hash table just below IFP. Set SRC to point to it.
	SEC
	LDA	IFPL
	SBC	#POOLSIZE
	STA	SRCL
	LDA	IFPH
	SBC	#0
	STA	SRCH

	; Hash the key (the value of IP) to determine which linked list to
	; work with. The hash is simply IPL & HASHMASK; this takes the low
	; n bits excluding bit 0, which should be fairly well distributed and
	; can be directly used as an index into the hash table.
	LDA	IPL
	AND	#HASHMASK
	CLC
	ADC	SRCL
	STA	HEADPTR
	LDA	SRCH
	ADC	#0
	STA	HEADPTR+1

	; Initialise THISPTR with the address (possibly 0) of the first
	; linked list entry.
	LDY	#0
	LDA	(HEADPTR),Y
	STA	THISPTR
	INY
	LDA	(HEADPTR),Y
	STA	THISPTR+1

NEXTENTRY
	; THISPTR contains the address of the linked list element to consider.
	; If THISPTR is null, we've failed to find a match and
	; we need to create a new entry. Otherwise it's a match and we want
	; to return the address of the string within the THISPTR entry.
	LDA	THISPTR
	ORA	THISPTR+1
	BEQ	ATENDOFLIST
	; Does the element pointed to by THISPTR have a matching IP value?
	LDY	#0
	LDA	(THISPTR),Y
	INY
	CMP	IPL
	BNE 	NOTMATCH
	LDA	(THISPTR),Y
	CMP	IPH
	BEQ	MATCH
NOTMATCH
	; It didn't match, so put the address of the next element into THISPTR
	; and loop round. Y=1 at this point.
	INY
	LDA	(THISPTR),Y
	PHA
	INY
	LDA	(THISPTR),Y
	STA	THISPTR+1
	PLA
	STA	THISPTR
	JMP	NEXTENTRY

MATCH
	; The string is in the pool, starting at (THISPTR),4.
	CLC
	LDA	#4
	ADC	THISPTR
	STA	ESTKL,X
	LDA	THISPTR+1
	ADC	#0
	STA	ESTKH,X
	JMP	CSDONE

ATENDOFLIST

	; We hit the end of the list, so this string isn't in the pool. We
	; need to create a new entry, which we insert at the head of the linked
	; list. We choose to insert at the head for two reasons: a) it makes it
	; easier to fix up PP after a longjmp() b) it might help speed up string
	; lookups in inner loops, since more recently allocated strings will be
	; found first.

	; Lower PP to allocate (string length+1)+4 bytes for the new linked
	; list entry. We first lower by string length+1 and set that
	; address as the return value of the CS opcode.
	LDY	#0
	LDA	(IP),Y
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
	; Copy the string into the pool. Y is already 0.
	LDA	(IP),Y
	TAY
	; TODO: Delete the following Apple-related comments which are not true here
-	LDA	(IP),Y		; ALTRD IS ON,  NO NEED TO CHANGE IT HERE
	STA	(PP),Y		; ALTWR IS OFF, NO NEED TO CHANGE IT HERE
	DEY
	CPY	#$FF
	BNE	-

	; Lower PP a further 4 bytes for the first part of the entry.
	SEC
	LDA	PPL
	SBC	#4
	STA	PPL
	BCS	+
	DEC	PPH
+
	+CHECKVSHEAP PP
	
	; Copy IP to offset 0 of the new entry. Y is $FF.
	LDA	IPL
	INY
	STA	(PP),Y
	LDA	IPH
	INY
	STA	(PP),Y
	; Link the new entry in at the head of the list. Y is 1.
	; a) Make the previous head this entry's next.
	DEY
	LDA	(HEADPTR),Y
	LDY	#2
	STA	(PP),Y
	DEY
	LDA	(HEADPTR),Y
	LDY	#3
	STA	(PP),Y
	; b) Now make this entry the new head.
	LDY	#0
	LDA	PPL
	STA	(HEADPTR),Y
	INY
	LDA	PPH
	STA	(HEADPTR),Y

CSDONE
	; We're done.
	LDY	#0
	LDA	(IP),Y		; SKIP TO NEXT OP ADDR AFTER STRING
	TAY
	JMP	NEXTOP
}
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
	; TODO: START TEMP DEBUG
	CPX #(ESTKSZ/2)+1
	BCC TODOOK2
	BRK
	!BYTE $99
	!TEXT "Boom!"
	BRK
TODOOK2

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
+	LDY	#$02
	;* TODO: Following check semi-temp hack
	CPX 	#1+(ESTKSZ/2)
	BCC	TODOOK
	BRK
	BRK
	!TEXT "Foo!"
	BRK
TODOOK
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
+	RTS
;
RET	LDA	IFPL		; DEALLOCATE POOL
	STA	PPL
	LDA	IFPH
	STA	PPH
 	CLC			; RESTORE PREVIOUS FRAME
	PLA
	ADC	PPH
	STA	IFPH
	CLC
	PLA
	ADC	PPL
	STA	IFPL
	BCC	++
	INC	IFPH
++	RTS
}
!IFNDEF PLAS128 {
	STA	IFPL
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
	;* entry. This isn't a perfect solution as the expression stack
	;* can shrink after the setjmp() and before the longjmp(),
	;* so important state could still be lost. setjmp.pla is an
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

SEGEND	=	*
;* TODO: Tidy up zero page use

VMINITPOSTRELOC
	LDX	#$FF
	TXS

!IFDEF PLAS128 {
;* PLAS128 isn't second processor compatible. The load/exec addresses are set
;* to force it to load in the host, and we then need to forcibly disable the
;* second processor. See:
;* http://stardot.org.uk/forums/viewtopic.php?f=54&t=12416&p=158560#p158560
;* and note that the logic to disable the second processor is based on the
;* TubeOff command at http://mdfs.net/Software/Tube/BBC/TubeSwitch
	LDA	tube_presence_flag
	BPL	.NOTTUBE
	; The tube host code will have claimed EVNTV and BRKV so we need to
	; claim them. The standard initialisation code always claims BRKV,
	; but we need to make EVNTV point to an RTS.
	LDA	#<ANRTS
	STA	EVNTV
	LDA	#>ANRTS
	STA	EVNTV+1
	; Reset the tube presence flag
	LDA	#$00
	STA	tube_presence_flag
	; "Initialise ROMs"; this issues service call $37, but that isn't
	; documented. This is what TubeOff does...
	LDA	#osbyte_issue_service_call
	LDX	#$37
	JSR	OSBYTE
	; Read current filing system number
	LDA	#$00
	TAY
	JSR	OSARGS
	; Re-select the current filing system
	TAY
	LDA	#osbyte_issue_service_call
	LDX	#service_call_select_filing_system
	JSR	OSBYTE
	; The tube is now disabled and we can continue as if it had never
	; been turned on. (However, we'll have less memory available on a
	; B or B+, as the tube host code will have issued *FX20,6 and
	; OSHWM will be &600 bytes higher as a result.)
.NOTTUBE
}
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

	;* If we're running on a second processor, we use memory up to $F800; we
	;* ignore what OSBYTE $84 says.
	LDA	#osbyte_read_high_order_address
	JSR	OSBYTE
	TYA
	BMI	NOTTUBE
	;* We're on a second processor; we set PROG at $EE to VMINITPOSTRELOC
	;* so that the VM is re-initialised correctly on BREAK.
	LDA	#<VMINITPOSTRELOC
	STA	$EE
	LDA 	#>VMINITPOSTRELOC
	STA	$EF
	LDY	#$F8
	LDA 	#<VMINIT	; SAVE HEAP START - we can't overwrite from SEGEND
	STA	SRCL		; because on BREAK we will re-enter VMINITPOSTRELOC
	LDA	#>VMINIT
	STA	SRCH
	BNE	INITFP
NOTTUBE
	LDA	#<SEGEND	; SAVE HEAP START
	STA	SRCL
	LDA	#>SEGEND
	STA	SRCH
	LDA	#osbyte_read_himem
	JSR	OSBYTE
INITFP	LDX	#$00
	STX	IFPL		; INIT FRAME POINTER
	STY	IFPH
!IFDEF PLAS128 {
	STX	PPL
	STY	PPH
}
	STY	HIMEMH
	LDX	SRCH
	INX
	INX
	CPX	IFPH
	BCC	+
	JMP	INITNOROOM
+	LDX	#ESTKSZ/2	; INIT EVAL STACK INDEX
;* Install BRK handler
	LDA	#<BRKHND
	STA	BRKV
	LDA	#>BRKHND
	STA	BRKV+1

	JMP	A1CMD

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
	LDA	#osbyte_read_oshwm
	JSR	OSBYTE
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
	BEQ	ADVANCE255
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

ADVANCE255
	CLC
	LDA	CODEPL
	ADC	#255
	STA	CODEPL
	BCC 	RELPATCHNEXT
	INC	CODEPH
	BNE	RELPATCHNEXT	; ALWAYS BRANCHES

VMRELOCCOUNT
	!WORD $0000
VMRELOC				; MUST BE LAST LINE OF FILE
