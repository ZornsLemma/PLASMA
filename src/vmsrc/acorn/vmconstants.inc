;**********************************************************
;*
;* ACORN VM CONSTANTS
;*
;**********************************************************

;* TODO: These should probably be "last" in page 4, then the symbol
;* table can start on top of these bytes in PLAS32 to avoid wasting
;* them there. (Actually I'm not sure that's an issue. We can
;* conditionally compile both this and bbcmd.pla to start the
;* symbol table at a different address in PLAS32 and PLAS128 if we
;* wish. Though in general we should try to keep the addresses
;* consistent, *especially* of things like errfp and errjb that may
;* get compiled into modules.)
; SFTODO?! CURRENTLY BREAKS ACMETOPLASMA !IFDEF PLAS128 {
RAMBANK = $400		; 4 byte table of RAM bank numbers
RAMBANKCOUNT = $404
; SFTODO?! }

; When an OS error occurs, our BRKV handler transfers control to the
; code whose address is at ERRFP. This is typically the error_hander()
; function.
ERRFP  = $405		; 2 bytes
; error_handler() performs a longjmp using the jmp_buf at the address
; stored at ERRJB.
ERRJB  = $407		; 2 bytes

; SFTODO: TEMPORARY/DOCUMENT IF KEEP
JITCOMP = $409 		; 2 bytes
JITCODEPTR = $40B		; 2 bytes

; SFTODO: I WOULD LIKE THE JITIINTERP ADDRESS TO NOT BE WASTED ON NON-JIT VIMS IF POSSIBLE
; Addresses of VM entry points
INTERPPTR = $40D
IINTERPPTR = $40F
JITIINTERPPTR = $411

; We use the 256 bytes at $0700 for two purposes - as an input buffer
; for gets() and to hold the error number and error string after an
; OS error occurs.
INBUFF = $700
INBUFFSZ = 255
ERRNUM = $700
ERRSTR = $701
ERRSTRSZ = 255

; TODO: Poor formatting above

