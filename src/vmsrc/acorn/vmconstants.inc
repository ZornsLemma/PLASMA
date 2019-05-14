;**********************************************************
;*
;* ACORN VM CONSTANTS
;*
;**********************************************************

; When an OS error occurs, our BRKV handler transfers control to the
; code whose address is at ERRFP. This is typically the error_hander()
; function.
ERRFP  = $400		    ; 2 bytes
; error_handler() performs a longjmp using the jmp_buf at the address
; stored at ERRJB.
ERRJB  = $402		    ; 2 bytes

; We allocate space for JITCOMP even in non-JIT VMs; this wastes a little space
; in low memory but it means we can guard against users accidentally doing things
; like loading the JIT module on a non-JIT VM and causing odd behaviour.
JITCOMP = $404		    ; 2 bytes

; Addresses of VM entry points. plvm-post.s assumes all two or three entry points are
; contiguous, so JIINTERPTR must follow the first two if it is defined.
INTERPPTR = $406	    ; 2 bytes
IINTERPPTR = $408	    ; 2 bytes
NEXT0 = IINTERPPTR+2
!IFDEF JIT {
    JITIINTERPPTR = NEXT0   ; 2 bytes, address of JIT VM entry point
    NEXT1 = JITIINTERPPTR+2
} ELSE {
    NEXT1 = NEXT0
}

; Now we start allocating space for build-specific features. Anything common to
; all builds should come before this point, because it's unnecessarily confusing
; to have gratuitous differences and if common addresses are baked into modules we
; must keep the addresses constant to make the modules compatible with all VM builds.

!IFDEF JIT {
    JITCODEPTR = NEXT1	    ; 2 bytes, address of next free byte in JIT buffer
    !IFDEF PLAS128 {
	JITMEMCPY = JITCODEPTR+2 ; 2 bytes, address of memcpy()
	NEXT2 = JITMEMCPY+2
    } ELSE {
	NEXT2 = JITCODEPTR+2
    }
} ELSE {
    NEXT2 = NEXT1
}

!IFDEF PLAS128 {
    RAMBANKCOUNT = NEXT2    ; 1 byte count of RAM banks found
    RAMBANK = NEXT2+1	    ; 4 byte table of RAM bank numbers
    NEXT3 = RAMBANK+4
} ELSE {
    NEXT3 = NEXT2
}

LOWSYMTBLCHUNK = NEXT3
LOWSYMTBLCHUNKSZ = $700 - LOWSYMTBLCHUNK ;; $50 ;; // $150 // TODO $02f7 (OR SHOULD PROBABLY BE '$0700 - lowsymtblchunk' OR SIMILAR) (NOT $0700 BUT A CONSTANT FROM VMCONSTANTS.INC)

; We use the 256 bytes at $0700 for two purposes - as an input buffer
; for gets() and to hold the error number and error string after an
; OS error occurs.
INBUFF = $700
INBUFFSZ = 255
ERRNUM = $700
ERRSTR = $701
ERRSTRSZ = 255

; Second processor memory allocations
TUBERAMTOP = $F800
TUBEJITBUFFERSIZE = 8*1024/256 ; pages
TUBEJITHEAPTOP = TUBERAMTOP-(TUBEJITBUFFERSIZE*256)

; Maximum number of characters in a module name; need an extra byte for a PLASMA string.
MAXNAMELEN = 16

; Error codes; these don't have to follow any scheme except that language errors should be
; in the range 0-127, but I've tried to break them up into blocks.
;
; Core machine code VM errors
ERRSTACK = 1
; Core PLASMA-code VM errors
ERRHEAPFULL = 16
ERRBADMODULE = 17
ERRBADMODE = 25 ; same code used by BASIC
; JIT errors
ERRNOJITSUPPORT = 32
ERRNOJITLOADED = 33
; Library module errors
ERRBADLIBPATH = 48
; Non-language errors we generate by analogy with errors thrown by filing systems
ERRBADNAME = 204 ; SFTODO: SHOULD THIS BE USING THIS ERR NUM? WOULD ONE IN THE 0-127 RANGE BE BETTER? NOT THINKING NOW, JUST CHECK LATER... MAY WELL BE FINE
ERRNOTFOUND = 214 ; same code used by filing systems for "Not found" error

; TODO: Poor formatting above
