# Architecture

<!-- toc -->
- [Summary](#summary)
- [Design Details](#design-details)
  - [Architecture](#architecture)
  - [crau-agent](#crau-agent)
  - [Log analysis tools](#log-analysis-tools)
<!-- /toc -->

## Summary

This document provides an architectural overview of the
crypto-auditing project.

## Design Details

The following figure illustrates the proposed architecture.

![](architecture.svg)

At the highest level, the architecture consists of two parts:
crau-agent and log analysis tools (crau-query, crau-monitor).

crau-agent runs as a system service, receives cryptographic events
from the kernel through eBPF, and writes them onto the primary log
file.

Log analysis tools provide users with access to the primary log
storage.

### crau-agent

The responsibilities of crau-agent include:

- Install BPF program to monitor USDT events
- Receive notification events on execution reaching USDT probes
- Write received events to primary log file

The agent is meant to work as fast as possible with minimal resource
consumption. The current implementation leverages [eBPF ring buffers]
and [io_uring] for asynchronous I/O.

### Log analysis tools

The log analysis tools provides ways to access the primary log file,
either at any later time or at real-time.

The current implementation contains crau-query for the former, and
crau-monitor for the latter.

[BPF ring buffer]: https://www.kernel.org/doc/html/latest/bpf/ringbuf.html
[io_uring]: https://en.wikipedia.org/wiki/Io_uring
