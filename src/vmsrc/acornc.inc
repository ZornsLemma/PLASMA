;**********************************************************
;*
;* ACORN OS CONSTANTS
;*
;**********************************************************

OSFIND = $FFCE
OSGBPB = $FFD1
OSBPUT = $FFD4
OSBGET = $FFD7
OSARGS = $FFDA
OSFILE = $FFDD
OSRDCH = $FFE0
OSWRCH = $FFEE
OSWORD = $FFF1
OSBYTE = $FFF4
OSCLI  = $FFF7

osbyte_read_high_order_address = $82
osbyte_read_oshwm              = $83
osbyte_read_himem              = $84

;**********************************************************
;*
;* ACORN VM CONSTANTS
;*
;**********************************************************
;*
;* These must be kept in sync with vmsrc/bbcmd.pla.

;* TODO: These should probably be "last" in page 4, then the symbol
;* table can start on top of these bytes in PLAS32 to avoid wasting
;* them there.
!IFDEF PLAS128 {
RAMBANK = $400		; 4 byte table of RAM bank numbers
RAMBANKCOUNT = $404
}

; When an OS error occurs, our BRKV handler transfers control to the
; code whose address is at ERRFP. This is typically the error_hander()
; function.
ERRFP  = $405		; 2 bytes
; error_handler() performs a longjmp using the jmp_buf at the address
; stored at ERRJB.
ERRJB  = $407		; 2 bytes

; We use the 256 bytes at $0700 for two purposes - as an input buffer
; for rdstr() and to hold the error number and error string after an
; OS error occurs.
INBUFF = $700
INBUFFSZ = 255
ERRNUM = $700
ERRSTR = $701

; TODO: Poor formatting above
