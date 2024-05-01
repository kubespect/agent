SHELL=/bin/bash

.PHONY: help bpf
.DEFAULT_GOAL := build
.ONESHELL:

ARCH=$(shell uname -m)
ifeq ($(ARCH), $(filter $(ARCH), aarch64 arm64))
	BPF_TARGET=arm64
	BPF_ARCH_SUFFIX=arm64
else
	BPF_TARGET=amd64
	BPF_ARCH_SUFFIX=x86
endif

GOCMD := go
GOBUILD := $(GOCMD) build
GOGENERATE := $(GOCMD) generate
GOTEST := $(GOCMD) test
GOTOOL := $(GOCMD) tool
CLANG := clang

