PROJECT_DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))

VMLINUX_H := $(PROJECT_DIR)/vmlinux.h
VMLINUX_BTF := /sys/kernel/btf/vmlinux
BPFTOOL := sudo bpftool
CLANG := clang
LLC := llc
VMLINUX_INCLUDE_DIR := /usr/include/linux/

HAS_VMLINUX_BTF := $(wildcard $(VMLINUX_BTF))

help:
	@echo "Available targets:"
	@echo "  generate         - Run go generate to generate eBPF code"
	@echo "  build            - Build the Go application"
	@echo "  gen-vmlinux      - Generate vmlinux.h from kernel BTF"
	@echo "  clean            - Clean generated files"

gen-vmlinux:
ifeq ($(HAS_VMLINUX_BTF),)
	$(error "/sys/kernel/btf/vmlinux not found, please ensure CONFIG_DEBUG_INFO_BTF=y and bpftool is installed")
endif
	$(BPFTOOL) btf dump file $(VMLINUX_BTF) format c > $(VMLINUX_H)
	@echo "Generated vmlinux.h at $(VMLINUX_H)"

generate: $(VMLINUX_H)
	go generate ./...

build: generate
	go build -o tracer main.go

clean:
	rm -f $(VMLINUX_H)
	rm -f *.go *.ebpf.go