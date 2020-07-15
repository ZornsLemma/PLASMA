;**********************************************************
;*
;*                 VM ZERO PAGE LOCATIONS
;*
;**********************************************************
;* TODO: This has been minimally tweaked for BBC support; it could possibly
;* be tweaked further. It would be good if the VM's zero page use was all
;* contiguous, leaving the rest of the language zp available for the user.
;* TODO: This has been tweaked a bit further but it might still be worth
;* rearranging a little more.
SRC	=	$00
SRCL	=	SRC
SRCH	=	SRC+1
DST	=	SRC+2
DSTL	=	DST
DSTH	=	DST+1
; int32.pla does this, so we need to allow space for it
; ACCUM32 = DSTH+1 ; 4 bytes
ZPCODE  =       DSTH+1+4
ZPCODESZ =	$10
; SFTODO: So we could start something eg ESTK at ZPCODE+ZPCODESZ (but be careful with PAD; final version should really calculate addresses in a sequence and we should have ESTK=PAD+2 rather than PAD=ESTK-2)
ESTKSZ	=	$20
; Some VM opcodes (e.g. LB) use ESTKH-1,X as temporary workspace (to
; allow the use of (ESTKH-1,X) addressing); some do the same trick with
; ESTKH-2,X. If ESTK is full (X=0), this will access one or two bytes
; below ESTKH - we set these aside as PAD. This space is available for
; temporary use if necessary in other code.
PAD     =       ZPCODE+ZPCODESZ
; SFTODO: It might be nice to arrange for ESTK to be at a multiple-of-$10 address, for minor improved readability in a page-aligned hex dump
ESTK	=	PAD+2
ESTKH	=	ESTK
ESTKL	=	ESTK+ESTKSZ/2
VMZP	=	ESTK+ESTKSZ
ESP     =       VMZP
IFP	=	ESP+1
IFPL	=	IFP
IFPH	=	IFP+1
PP      =	IFP+2
PPL	=	PP
PPH	=	PP+1
IPY	=	PP+2
JMPTMP	=	IPY+1
TMP	=	JMPTMP+1
TMPL	=	TMP
TMPH	=	TMP+1
HIMEMH  =       TMP+2 ; TODO: doesn't need to be in zp
; int32.pla uses TMP+3 as DVSIGN (1 byte) so we need to ensure that's not used
; by anything valuable.
SCRATCH =	TMP+3 ; SCRATCHSZ bytes
SCRATCHSZ =	$11
HEAPPTR =       SCRATCH+SCRATCHSZ
HEAPL   =	HEAPPTR
HEAPH   =  	HEAPL+1
VMZPTOP =       HEAPH+1
; There's nothing magic about $70 but for compatibility with BASIC I'd like to
; have $70-$8F inclusive free for the user. (Probably all of language zp from
; $70 up will be available, but I don't want to commit tothat yet.)
!IF VMZPTOP >= $70 {				   	; ACMEONLY
  !ERROR "VM zero page overrunning user zero page"	; ACMEONLY
}							; ACMEONLY
