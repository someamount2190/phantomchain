pkill -9 java 2>/dev/null; sleep 1
mkdir -p /root/pcdata
cat > /root/run-node.sh <<'EOF'
#!/bin/bash
exec java -Xmx256m -cp "/root/deploy/out:/root/deploy/lib/*" com.phantomchain.debug.NodeMain "$@" /root/pcdata
EOF
chmod +x /root/run-node.sh
for i in 0 1 2; do
port=$((9091+i))
cat > /etc/systemd/system/pcnode$i.service <<EOF
[Unit]
Description=PhantomChain node$i
After=network.target
[Service]
ExecStart=/root/run-node.sh $i $port 127.0.0.1:$port 127.0.0.1:9091
Restart=always
RestartSec=5
[Install]
WantedBy=multi-user.target
EOF
done
systemctl daemon-reload
systemctl enable pcnode0 pcnode1 pcnode2 >/dev/null 2>&1
systemctl start pcnode0; sleep 8
systemctl start pcnode1 pcnode2; sleep 16
for i in 0 1 2; do echo node$i=$(systemctl is-active pcnode$i); done
echo MEM; free -m | head -2