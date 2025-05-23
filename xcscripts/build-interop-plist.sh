#!/bin/sh

if [ $# -lt 2 ]; then
	2>&1 echo "Usage: $0 [inplist] [outplist]"
	exit 1
fi

inplist=$1
outplist=$2

impls="openrsync samba"
roles="sender receiver"

# Truncate
:> "$outplist"

echo "		<!-- @""generated by build-interop-plist.sh -->" >> "$outplist"
echo "#define	RSYNC_ROLE_SENDER	1" >> "$outplist"
echo "#define	RSYNC_ROLE_RECEIVER	2" >> "$outplist"

# Walk through all of our permutations; we can do each implementation against
# itself in sender/receiver modes, as well as against each other in
# sender/receiver modes.  We also test each of these combinations with client
# and server implementation swapped, just for completeness.
for client in $impls; do
	uclient=$(echo "$client" | tr '[[:lower:]]' '[[:upper:]]')
	echo "#define	RSYNC_CLIENT_${uclient}	1" >> "$outplist"
	for server in $impls; do
		userver=$(echo "$server" | tr '[[:lower:]]' '[[:upper:]]')
		echo "#define	RSYNC_SERVER_${userver}	1" >> "$outplist"

		# For client-sender, we want to prepend localhost: to the
		# destination.  For client-receiver, we want to prepend
		# localhost: to the sources.
		cat <<EOF >> "$outplist"
		<!-- client: ${client}, server: ${server} -->
EOF
		for crole in $roles; do
			suffix="${client}-${server}_c${crole}"
			srcprefix=""
			destprefix=""
			sendmacro=""
			rcvmacro=""
			if [ "$client" = "samba" -a "$client" = "$server" -a "$crole" = "receiver" ]; then
				cat <<EOF >> "$outplist"
			<!-- OMITTED: $crole -->
EOF
				continue
			fi
			cat <<EOF >> "$outplist"

			<!-- ROLE: $crole -->
EOF

			case "$crole" in
			sender)
				destprefix="local@localhost:"
				sendmacro="RSYNC_SENDER_${uclient}"
				rcvmacro="RSYNC_RECEIVER_${userver}"
				clrole="RSYNC_ROLE_SENDER"
				;;
			receiver)
				srcprefix="local@localhost:"
				rcvmacro="RSYNC_RECEIVER_${uclient}"
				sendmacro="RSYNC_SENDER_${userver}"
				clrole="RSYNC_ROLE_RECEIVER"
				;;
			esac

			echo "#define	RSYNC_CLIENT_ROLE	$clrole" >> "$outplist"
			echo "#define	${sendmacro}	1" >> "$outplist"
			echo "#define	${rcvmacro}	1" >> "$outplist"

			# Each of these variables are honored by the rsync()
			# shim in the testsuite's lib.sh
			cat <<EOF | sed -f - "$inplist" >> "$outplist"
/ATF_SH/i\\
				<key>RSYNC_CLIENT</key>\\
				<string>/AppleInternal/Tests/rsync/rsync.$client</string>\\
				<key>RSYNC_SERVER</key>\\
				<string>/AppleInternal/Tests/rsync/rsync.$server</string>\\
				<key>RSYNC_PREFIX_SRC</key>\\
				<string>$srcprefix</string>\\
				<key>RSYNC_PREFIX_DEST</key>\\
				<string>$destprefix</string>\\
				<key>RSYNC_SSHKEY</key>\\
				<string>\$HOME/.ssh/id_openrsync</string>\\
				<key>cstream</key>\\
				<string>/AppleInternal/Tests/rsync/openrsync/cstream</string>
/TestName/ {
n
s,</string>,__$suffix</string>,
}
EOF

			echo "#undef ${sendmacro}" >> "$outplist"
			echo "#undef ${rcvmacro}" >> "$outplist"
			echo "#undef RSYNC_CLIENT_ROLE" >> "$outplist"
		done

		echo "#undef RSYNC_SERVER_${userver}" >> "$outplist"
	done
	echo "#undef RSYNC_CLIENT_${uclient}" >> "$outplist"
done
