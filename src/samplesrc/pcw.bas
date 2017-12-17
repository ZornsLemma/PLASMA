REM Personal Computer World benchmarks (from December 1986 issue)
MODE 7
T%=TIME
PRINT "Start"
X%=0
Y%=9
FOR I%=1 TO 1000
X%=X%+(Y%*Y%-Y%)/Y%
NEXT
PRINT "Finish",X%
A%=TIME-T%
IF X%<>8000 THEN PRINT "Wrong!":END
MODE 3
T%=TIME
PRINT "Start"
FOR I%=1 TO 1000
PRINT "1234567890qwertyuiop",I%
NEXT
PRINT "Finish"
B%=TIME-T%
MODE 5
T%=TIME
PRINT "Start"
FOR X%=8 TO 800 STEP 8
FOR Y%=4 TO 400 STEP 4
PLOT 69,X%,Y%
NEXT
NEXT
PRINT "Finish"
C%=TIME-T%
MODE 7
T%=TIME
PRINT "Start"
F%=OPENOUT("X.TEST")
FOR I%=1 TO 1000
PRINT #F%,"1234567890qwertyuiop"
NEXT
CLOSE #F%
*DELETE X.TEST
PRINT "Finish"
D%=TIME-T%
MODE 7
Z%=@%
@%=&2020A
PRINT "intmath",A%/100
PRINT "textscrn",B%/100
PRINT "grafscrn",C%/100
PRINT "store",D%/100
@%=Z%
