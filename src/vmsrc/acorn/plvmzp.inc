;**********************************************************
;*
;*                 VM ZERO PAGE LOCATIONS
;*
;**********************************************************
;* TODO: This has been minimally tweaked for BBC support; it could possibly
;* be tweaked further. It would be good if the VM's zero page use was all
;* contiguous, leaving the rest of the language zp available for the user.
SRC	=	$06
SRCL	=	SRC
SRCH	=	SRC+1
DST	=	SRC+2
DSTL	=	DST
DSTH	=	DST+1
ESTKSZ	=	$20
ESTK	=	$50
; Some VM opcodes (e.g. LB) use ESTKH-1,X as temporary workspace (to allow the use of (ESTKH-1,X)
; addressing). If ESTK is full (X=0), this will access one byte below ESTKH - we set this aside as
; PAD. It is available for temporary use if necessary in other code.
PAD 	=	ESTK-1
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
TMP	=	IPY+1
TMPL	=	TMP
TMPH	=	TMP+1
HIMEMH  =       TMP+2 ; TODO: doesn't need to be in zp
SCRATCH =	TMP+3 ; 16 bytes
HEAPL   =       SCRATCH+16
HEAPH   =  	HEAPL+1
