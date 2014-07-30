#!/bin/bash
# Copyright 2014 Jose Ramón Lambea
#
# This file is part of Spageek KeygenMaker.
#
# Spageek KeygenMaker is free software: you can redistribute it
# and/or modify it under the terms of the GNU General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# Spageek KeygenMaker is distributed in the hope that it will be
# useful, but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General
# Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with Spageek KeygenMaker. If not, see http://www.gnu.org/licenses/.

# This is a p.o.c. for a keygenmaker for Linux

SRC_DIR="./src/"
TPL_DIR="./templates/"

clear

echo "Hi dear Hacker, what source file you want to use?"

select var in `ls -1 "${SRC_DIR}"`
do
	
	if !(( `echo ${REPLY} | grep '^[!0-9]*$'` )) || (( "${REPLY}" > `ls -1 "${SRC_DIR}" | wc -l` )) ; then
		echo "A bad option has chosen, exiting."
		exit 1
	fi

	SRC2USE="${SRC_DIR}${var}"
	break

done

echo -e "Targeted ${SRC2USE} as target source code template.\n"

echo "What template file you want to use?"
select var in `ls -1 $TPL_DIR`
do

	if !(( `echo ${REPLY} | grep '^[!0-9]*$'` )) || (( "${REPLY}" > `ls -1 "${TPL_DIR}" | wc -l` )) ; then
		echo "A bad option has chosen, exiting."
		exit 1
	fi

	TPL2USE="${TPL_DIR}${var}"
	break
done

echo -e "Targeted ${TPL2USE} as target GUI code template.\n"

echo "OK, let's code, press [Ctrl+D] to end coding:"
cat > algorithm.tmp

ALG2USE=`cat algorithm.tmp | tr '\n' ' '`

echo -e "Please review your code and check if is fine, is correct?[Y/n] "
read result

if [[ $result == "Y" ]]; then
	echo "Let's make! :D"
else
	exit 5
fi

cat $SRC2USE | sed -e "s~\#\#TPL_FILE\#\#~\"""${TPL2USE}""\"~" -e "s~\#\#ALGORITHM\#\#~""${ALG2USE}""~" > result.vala

echo "Compiling..."
valac --pkg gtk+-3.0 --pkg gmodule-2.0 result.vala 2> compile.err

ls -ltr result
