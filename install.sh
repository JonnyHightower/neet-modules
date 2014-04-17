#!/bin/bash

##########################################################################
#
#    Neet: Network discovery, enumeration and security assessment tool
#    Copyright (C) 2008-2014 Jonathan Roach
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
#    Contact: jonnyhightower [at] funkygeek.com
#
##########################################################################

# This is the installer for the Neet modules
export NEET=/opt/neet
export CONFIDR="${NEET}/etc"
export VERSION=`cat VERSION`
export INST="$PWD"

if [ ! -d "$NEET" ]; then
	echo "Couldn't find neet installation. Exiting."
	exit 1
fi

. ${NEET}/core/installsupport

if [ ! -z $INVOKEDBYNEETUPDATE ] && [ $INVOKEDBYNEETUPDATE -eq 1 ]; then
	echo -n "   + Installing neet module updates..."
	FILESTOREMOVE=""
	for file in $FILESTOREMOVE; do
		rm -f "$file"
	done
	#######################################################

	mkdir -p "${NEET}/modules/"
	mkdir -p "${NEET}/resources/modules/"

	# The real modules
	cd "${INST}/content"
	for module in *; do
		if [ -f "${module}/${module}.gsm" ]; then
			cd "$module"
			# Install the module
			cp "${module}.gsm" "${NEET}/modules/"

			# Install whatever resources the module needs into the resource directory
			auxin=0
			for aux in `ls | grep -v .gsm | grep -v install.sh`; do
				if [ $auxin -eq 0 ]; then
					rm -rf "${NEET}/resources/modules/$module"
					mkdir -p "${NEET}/resources/modules/$module" 2>/dev/null
					auxin=1
				fi	
				cp -R "$aux" "${NEET}/resources/modules/$module/"
			done
			# If the module needs special actions (needs config file info, or needs to write somewhere),
			# it should have this in its own install.sh script.
			if [ -x install.sh ]; then
				./install.sh
			fi
			cd "${INST}/content"
		fi
	done

	# Any templates
	cd "${INST}/content"
	for module in *; do
		if [ -f "${module}/${module}.gsm.temp" ]; then
			cd "$module"
			# Install the module
			cp "${module}.gsm.temp" "${NEET}/modules/"

			# Install whatever resources the module needs into the resource directory
			auxin=0
			for aux in `ls | grep -v .gsm | grep -v install.sh`; do
				if [ $auxin -eq 0 ]; then
					rm -rf "${NEET}/resources/modules/$module"
					mkdir -p "${NEET}/resources/modules/$module" 2>/dev/null
					auxin=1
				fi	
				cp -R "$aux" "${NEET}/resources/modules/$module/"
			done
			# If the module needs special actions (needs config file info, or needs to write somewhere),
			# it will have this in its own install.sh script.
			if [ -x install.sh ]; then
				./install.sh
			fi
			cd "${INST}/content"
		fi
	done

	#######################################################
	newVersion neet-modules $VERSION
	echo "done"
else
	echo "This package is for the neet-update script and should not be installed manually."
	exit 1
fi

exit 0

