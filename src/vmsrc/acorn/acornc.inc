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

; TODO: Using upper case for all these constants might be more consistent;
; that is the project convention for assembler code.

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

osargs_get_command_line_tail = $01

service_call_select_filing_system = $12

buffer_keyboard = $FF

; SFTODO: Keep?
vdu_gcol = 18
vdu_goto_xy = 31
