#!/bin/bash
/bin/rm znew # just paranoia, to prove pt.py is creating it
python pt.py || exit 1
sed -e 's/_F[0-9]*/_FXXXX/g' < zprev > zpreve
sed -e 's/_F[0-9]*/_FXXXX/g' < znew > znewe
meld zpreve znewe &
