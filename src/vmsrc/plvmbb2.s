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
