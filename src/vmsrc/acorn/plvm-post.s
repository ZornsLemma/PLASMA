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
	
	LDX	#$FF ;* SFTODO: A2 PORT USES $FE WITH COMMENT 'SEE GETS', I SUSPECT THIS DOESN'T APPLY TO BBC PORT BUT CHECK
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
	;* entry. This wouldn't a perfect solution as the expression stack
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

SEGEND	=	*
;* TODO: Tidy up zero page use

!IFDEF NONRELOCATABLE {
VMINIT
}
VMINITPOSTRELOC
	LDX	#$FF ;* SFTODO: A2 PORT USES $FE WITH COMMENT 'SEE GETS', I SUSPECT THIS DOESN'T APPLY TO BBC PORT BUT CHECK
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
	LDA	$2A1,Y
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
	LDY	#$D8 ; SFTODO: SHOULD BE $F8, TEMPORARY HACK TO ALLOCATE A CODE BUFFER FOR JIT
	LDA 	#<TUBEHEAP	; SAVE HEAP START - we can't overwrite from SEGEND
	STA	SRCL		; because on BREAK we will re-enter VMINITPOSTRELOC
	LDA	#>TUBEHEAP
	STA	SRCH
	;* SFTODO: TEMP HACK TO INITIALISE JITCODE - WE PROBABLY SHOULDN'T DO THIS ONLY ON TUBE CODE PATH BUT FOR NOW IT'S ALL AN EXPERIMENTAL HACK
	LDA	#$00
	STA	JITCODE
	; SFTODO: FOR TUBE, AT LEAST AS A HACK LDA	#$D8
	LDA #$B0 ; SFTODO: CRUDE HACK FOR PLAS128
	STA	JITCODE+1
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
	LDA	$FFFF,Y		; FETCHOP, IP MAPS OVER $FFFF @ FETCHOP+1
	STA	OPIDX
	JMP	(OPTBL)
}

TUBEHEAP
!IFNDEF NONRELOCATABLE {
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
}
