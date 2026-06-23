echo realjava=$(pgrep -x java | wc -l)
echo phantom_procs=$(ps -C java -o args= 2>/dev/null | grep -c phantomchain)
echo deploy=$(test -e /root/deploy && echo present || echo gone)
echo swap=$(swapon --show | wc -l)
echo uptime=$(awk '{print int($1)}' /proc/uptime)s