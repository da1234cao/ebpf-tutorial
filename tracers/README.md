
# 使用手册

```shell
apt install libbpf-dev
make build

./tracer -h
./tracer
root@ubuntu24-1 ~/w/s/e/tracers (laboratory)# ./tracer
2025/06/07 19:35:38 Starting...
2025/06/07 19:35:38 TcpTracer: true
2025/06/07 19:35:39 attached tcp_v4_connect
2025/06/07 19:35:39 attached tcp_v6_connect
2025/06/07 19:35:39 attached tcp_close
2025/06/07 19:35:39 attached tcp_set_state
2025/06/07 19:35:39 attached kret inet_csk_accept
2025/06/07 19:35:39 attached kret tcp_v4_connect
2025/06/07 19:35:39 attached kret tcp_v6_connect
2025/06/07 19:35:50 Command: nc, Source Address: 192.168.1.6, Destination Address: 192.168.1.13, Source Port: 10000, Destination Port: 48344
2025/06/07 19:35:53 Command: curl, Source Address: 192.168.1.6, Destination Address: 103.235.46.102, Source Port: 42874, Destination Port: 80
2025/06/07 19:35:53 Command: curl, Source Address: 192.168.1.6, Destination Address: 103.235.46.102, Source Port: 42874, Destination Port: 80
```

# 不完善的地方

- ipv6 输出错误
- 无法区分数据包的方向(income/outging)