#! /bin/bash

#	sanity.sh -- a growing testsuite for unhide-tcp.
#
# Copyright (C) 2010 Patrick Gouin.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
# Original Author: Patrick Gouin

# remove pre-existing local ss
rm -f ./ps

#test 0
# Don't call ss : let all ports appear hidden
cat <<EOF
   
   ============  Test #0  ============
   Don't call ss : let all ports appear hidden.
   This should find all ports as hidden..

EOF
cat <<EOF >./ss
#! /bin/bash

false
EOF
chmod 754 ./ss
#PATH=.:$PATH ./unhide-tcp -fl
# PATH=.:$PATH ./unhide-tcp
PATH=.:$PATH ./unhide-tcp-double_check

# remove pre-existing local ss
rm -f ./ss

#test 1
# Call ss : let cups port appears hidden
cat <<EOF
   
   ============  Test #1  ============
   Call ss : let cups port appears hidden.
   This should find port 631 as hidden..

EOF
cat <<EOF >./ss
#! /bin/bash

# echo "Le 1er paramètre est  : \$1" >&2
# echo "Le 2ème paramètre est : \$2" >&2
# echo "Le 3ème paramètre est : \$3" >&2
# echo "Le 4ème paramètre est : \$4" >&2

if [ "\$4" != ":631" ]
then
   # appelle le véritable ss
   /sbin/ss \$@
else
   echo "Le 4ème paramètre est : \$4" >&2
fi

EOF
chmod 754 ./ss
# PATH=.:$PATH ./unhide-tcp -fl
PATH=.:$PATH ./unhide-tcp-double_check -fl

# remove pre-existing local ss
#rm -f ./ss
