;**********************************************************
;*
;*                 VM ZERO PAGE LOCATIONS
;*
;**********************************************************

!IFNDEF BBC {
SRC     =   $06
SRCL    =   SRC
SRCH    =   SRC+1
DST     =   SRC+2
DSTL    =   DST
DSTH    =   DST+1
ESGUARD =   $BE
ESTKSZ  =   $20
ESTK    =   $C0
ESTKH   =   ESTK
ESTKL   =   ESTK+ESTKSZ/2
VMZP    =   ESTK+ESTKSZ
IFP     =   VMZP
IFPL    =   IFP
IFPH    =   IFP+1
PP      =   IFP+2
PPL     =   PP
PPH     =   PP+1
IPY     =   PP+2
ESP     =   IPY+1
JMPTMP  =   ESP+1
TMP     =   JMPTMP+1
TMPL    =   TMP
TMPH    =   TMP+1
}

;* TODO: This has been minimally tweaked for BBC support; it could possibly
;* be tweaked further. It would be good if the VM's zero page use was all
;* contiguous, leaving the rest of the language zp available for the user.
!IFDEF BBC {
SRC	=	$06
SRCL	=	SRC
SRCH	=	SRC+1
DST	=	SRC+2
DSTL	=	DST
DSTH	=	DST+1
ESTKSZ	=	$20
ESTK	=	$50
;* TODO: PORT APPLE TWEAKS TO ESTKL/ESTKH?
;* TODO: ESGUARD?
ESTKL	=	ESTK
ESTKH	=	ESTK+ESTKSZ/2
VMZP	=	ESTK+ESTKSZ
ESP     =       VMZP
DVSIGN	=	VMZP ;* TODO: BEEN REMOVED FROM APPLE PORT, REMOVE FROM BBC?
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
NPARMS	=	TMPL ; TODO: not used?!
FRMSZ	=	TMPH ; TODO: not used?!
HIMEMH  =       TMP+2 ; TODO: doesn't need to be in zp
SCRATCH =	TMP+3 ; 16 bytes
HEAPL   =       SCRATCH+16
HEAPH   =  	HEAPL+1
}
