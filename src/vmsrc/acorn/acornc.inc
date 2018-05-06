; SFTODO - POSSIBLY THIS SHOULD BE SYMLINKED INTO THE 'INC' DIRECTORY FOR THE ACORN PORT - I THINK IT IS IN PRINCIPLE USEFUL FOR WRITING GENERAL ASSEMBLY LANGUAGE CODE IN USER PROGRAMS ON THE ACORN PORT, SO IT ISN'T REALLY PART OF THE VM SOURCE CODE AS SUCH (ALTHOUGH THAT'S ONE OF ITS USES)
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
OSASCI = $FFE3
OSNEWL = $FFE7
OSWRCH = $FFEE
OSWORD = $FFF1
OSBYTE = $FFF4
OSCLI  = $FFF7

error_message_ptr = $FD

BRKV  = $0202
EVNTV = $0220

tube_presence_flag = $027A

osbyte_acknowledge_escape      = $7E
osbyte_get_buffer_status       = $80
osbyte_read_key                = $81
osbyte_read_high_order_address = $82
osbyte_read_oshwm              = $83
osbyte_read_himem              = $84
osbyte_issue_service_call      = $8F

service_call_select_filing_system = $12

buffer_keyboard = $FF

; SFTODO: Keep?
vdu_gcol = 18
vdu_goto_xy = 31

;**********************************************************
;*
;* ACORN VM CONSTANTS
;*
;**********************************************************
;*
;* These must be kept in sync with vmsrc/bbcmd.pla.

;* TODO: These should probably be "last" in page 4, then the symbol
;* table can start on top of these bytes in PLAS32 to avoid wasting
;* them there. (Actually I'm not sure that's an issue. We can
;* conditionally compile both this and bbcmd.pla to start the
;* symbol table at a different address in PLAS32 and PLAS128 if we
;* wish. Though in general we should try to keep the addresses
;* consistent, *especially* of things like errfp and errjb that may
;* get compiled into modules.)
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

; SFTODO: TEMPORARY/DOCUMENT IF KEEP
JITCOMP = $409 		; 2 bytes

; We use the 256 bytes at $0700 for two purposes - as an input buffer
; for rdstr() and to hold the error number and error string after an
; OS error occurs.
INBUFF = $700
INBUFFSZ = 255
ERRNUM = $700
ERRSTR = $701
ERRSTRSZ = 255

; TODO: Poor formatting above
