;* SFTODO: Formatting of code/comments in this file is very ugly/inconsistent -
;* in part because I'm trying to emulate Dave's style and doing so very badly.

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

SEGEND	=	*

;* Initialisation code which is executed on soft break on second processor; this
;* has to be split off from the one-off initialisation code so we can discard the
;* one-off initialisation code safely.
VMINITTUBESOFTBREAK
	!CPU	65C02

	LDA	#0		; on soft break we must have an empty command tail
VMINITTUBESOFTBREAK2
	STA	INBUFF

	LDA 	#<TUBEHEAP	; SAVE HEAP START - we can't overwrite from SEGEND
	STA	SRCL		; because on BREAK we will re-enter VMINITTUBESOFTBREAK
	LDA	#>TUBEHEAP
	STA	SRCH

	;* When we're running on a second processor, we use memory up to TUBERAMTOP/TUBEJITHEAPTOP; we
	;* ignore what OSBYTE $84 says.
!IFNDEF JIT {
	LDY	#>TUBERAMTOP
} ELSE {
	LDY	#>TUBEJITHEAPTOP
}
	;* Fall through to INITFP...
	!CPU	6502

;* Common initialisation code
INITFP	
	LDX	#$FF
	TXS

	LDX	#$00
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
	

;* The following initialisation doesn't need to be redone after a soft reset on a second
;* processor, so we can do it here and then the code can be discarded on all VMs after
;* initialisation.
TUBEHEAP
VMINITPOSTRELOC

;
; INSTALL PAGE 0 FETCHOP ROUTINE
;
	LDY	#ZPCODESZ
- 	LDA	PAGE0-1,Y
	STA	DROP-1,Y
	DEY
	BNE	-

;
; SET JMPTMP OPCODE
;
        LDA     #$4C
        STA     JMPTMP

;
; Populate the table of VM entry point addresses
;
	!IFNDEF JIT {
	    LDY #4
	} ELSE {
	    LDY #6
	}
EPLOOP
	LDA	VMENTRYPOINTTBL-1,Y
	STA	INTERPPTR-1,Y
	DEY
	BNE	EPLOOP


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

;* Copy any command line tail to INBUFF as a PLASMA-style string
;* Code based on the 6502 fragment at http://beebwiki.mdfs.net/Reading_command_line
;* We use this tube-compatible code in all cases; this code is discarded on all
;* versions so there's no harm in having the extra code when we don't need it.
	; Read address of command line parameters
	LDA	#$01 ; SFTODO MAGIC CONSTANTS
	LDY	#$00
	LDX	#SCRATCH
	JSR	OSARGS
RDCMDLP
	TYA
	PHA
	; Read byte from I/O memory
	LDX	#SCRATCH
	LDY	#$00
	LDA	#$05
	JSR	OSWORD
	; Copy byte to local buffer, stopping on CR
	PLA
	TAY
	LDA	SCRATCH+4
	CMP	#$0D
	BEQ	RDCMDLPDONE
	INY
	STA	INBUFF,Y
	; Increment command line address
	INC	SCRATCH
	BNE	RDCMDLP
	INC	SCRATCH+1
	JMP	RDCMDLP
RDCMDLPDONE
	; Save length at start of PLASMA-style string
	STY	INBUFF

	LDA	#osbyte_read_high_order_address
	JSR	OSBYTE
	TYA
	BMI	NOTTUBE
	;* We're on a second processor; we set PROG at $EE to VMINITTUBESOFTBREAK
	;* so that the VM is re-initialised correctly on BREAK.
	!CPU 65C02
	LDA	#<VMINITTUBESOFTBREAK
	STA	$EE
	LDA 	#>VMINITTUBESOFTBREAK
	STA	$EF
	;* And of course we need to do that initialisation now as well. The only
	;* difference is we don't want to set the command tail at INBUFF to an
	;* empty string.
	LDA	INBUFF
	JMP	VMINITTUBESOFTBREAK2
	!CPU 6502
NOTTUBE
	LDA	#<SEGEND	; SAVE HEAP START
	STA	SRCL
	LDA	#>SEGEND
	STA	SRCH
	LDA	#osbyte_read_himem
	JSR	OSBYTE
	JMP	INITFP

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
PAGE0END
!IF PAGE0END-PAGE0 > ZPCODESZ {
	!ERROR "PAGE0 code overflow"
}

;*
;* VM ENTRY POINTS
;*
; SFTODO: It's not a huge deal but it's annoying we have to have these when the core VM binary *knows* them at assembly time, we just don't have a way to get them into the PLASMA world. Is there any way round this? There's not a huge saving here because we need the first two to communicate the INTERP/IINTERP addresses to the separately compiled JIT module, but JITIINTERP is only used internally within the core VM and we wouldn't need space in page 4 for it if we could just make its address available as a constant in the PLASMA world somehow (persuade the PLASMA compile to emit '!BYTE CWopcode; !WORD JITIINTERP' in its output when we access a constant attached to JITIINTERP)
VMENTRYPOINTTBL
	!WORD	INTERP
	!WORD	IINTERP
	!IFDEF JIT {
	    !WORD   JITIINTERP
	}




VMINIT
;* The following bits of initialisation can generate errors (via BRK); by doing them before
;* relocation we reduce the chances of a harmless but mildly ugly "Bad program" error if
;* starting the VM from the BASIC prompt fails with an error.

;* We do this check here because it allows us to discard this code even on a
;* second processor.
!IFNDEF PLAS128 {
    !IFDEF JIT {
	;* The JIT isn't supported on flat PLASMA without a second processor; the main reason
	;* is that it assumes the JIT code buffer is above $8000.
	LDA	#osbyte_read_high_order_address
	JSR	OSBYTE
	TYA
	BPL	TUBE
	BRK
	!BYTE	$80
	;* Because this code is discarded at runtime on all platforms, we can be
	;* as verbose as we like in this error message without it costing anything
	;* except a bit of disk space. The message wording is tweaked to format nicely
	;* in both 40 and 80 column modes.
	!TEXT	"PLASJIT must run on a second processor; try P128JIT if you have sideways RAM."
	BRK
TUBE
    }
}

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
!IFDEF JIT {
	CPX	#$02
	BCS	ENOUGHRAM
	BRK
	!BYTE	$80
	!TEXT	"Only one bank of sideways RAM found"
	BRK
ENOUGHRAM
}
}

!IFDEF NONRELOCATABLE {
	JMP	VMINITPOSTRELOC
} ELSE {
				; RELOCATE CODE TO OSHWM
!IF <RELOCSTART != 0 {
	!ERROR "RELOCSTART must be on a page boundary"
}
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
	CPY	#(>RELOCSTART)+1
	BCC	RELOCOK		; We don't support relocating upwards
	BRK
	!BYTE	$80
	!TEXT	"PAGE too high"
	BRK
RELOCOK
	TYA
	STA	DSTH
	SEC
	SBC	#>RELOCSTART
	STA	DELTA
	LDA	#>RELOCSTART
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
	BYTESTOCOPY = VMINIT-RELOCSTART
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
