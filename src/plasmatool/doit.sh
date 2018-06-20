#!/bin/bash
python pt.py > znew || exit 1
sed -e 's/_F[0-9]*/_FXXXX/g' < zprev > zpreve
sed -e 's/_F[0-9]*/_FXXXX/g' < znew > znewe
meld zpreve znewe &
