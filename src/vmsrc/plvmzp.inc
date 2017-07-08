;**********************************************************
;*
;* VM ZERO PAGE LOCATIONS
;*
;**********************************************************

!IFNDEF BBC {
SRC	=	$06
SRCL	=	SRC
SRCH	=	SRC+1
DST	=	SRC+2
DSTL	=	DST
DSTH	=	DST+1
ESTKSZ	=	$20
XSTK	=	$A0
XSTKL	=	XSTK
XSTKH	=	XSTK+ESTKSZ/2
ESTK	=	$C0
ESTKL	=	ESTK
ESTKH	=	ESTK+ESTKSZ/2
VMZP	=	ESTK+ESTKSZ
ESP     =       VMZP
DVSIGN	=	VMZP
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
NPARMS	=	TMPL
FRMSZ	=	TMPH
DROP	=	$EF
NEXTOP	=	$F0
FETCHOP	=	NEXTOP+3
IP	=	FETCHOP+1
IPL	=	IP
IPH	=	IPL+1
OPIDX	=	FETCHOP+6
OPPAGE	=	OPIDX+1
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
ESTKL	=	ESTK
ESTKH	=	ESTK+ESTKSZ/2
VMZP	=	ESTK+ESTKSZ
ESP     =       VMZP
DVSIGN	=	VMZP
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
NPARMS	=	TMPL
FRMSZ	=	TMPH
HIMEMH  =       TMP+2 ; TODO: doesn't need to be in zp
SCRATCH =	TMP+3 ; 16 bytes
HEAPL   =       SCRATCH+16
HEAPH   =  	HEAPL+1
DROP	=	$1F
NEXTOP	=	$20
FETCHOP	=	NEXTOP+3
IP	=	FETCHOP+1
IPL	=	IP
IPH	=	IPL+1
OPIDX	=	FETCHOP+6
OPPAGE	=	OPIDX+1
}
