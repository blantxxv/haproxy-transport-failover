#!/bin/sh

check() {
	${HAPROXY_PROGRAM} -vv | grep -E '^Unit tests list :' | grep -q "srv_tf"
}

run() {
	${HAPROXY_PROGRAM} -U srv_tf
}

case "$1" in
	"check")
		check
	;;
	"run")
		run
	;;
esac
