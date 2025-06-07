# 使用

```shell
make build
root@ubuntu24-1 ~/w/s/e/go-hello (laboratory)# ./hello --interface=ens33
2025/06/07 22:10:21 Counting incoming packets on ens33..
2025/06/07 22:10:22 Received 25 packets
2025/06/07 22:10:23 Received 36 packets
2025/06/07 22:10:24 Received 46 packets
2025/06/07 22:10:25 Received 65 packets
2025/06/07 22:10:26 Received 80 packets
^C2025/06/07 22:10:26 Received signal, exiting..
```

# reference
- https://github.com/cilium/ebpf/blob/main/docs/ebpf/guides/getting-started.md