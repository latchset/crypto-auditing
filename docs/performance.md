# Measuring performance impact

## Summary

Auditing an application requires attaching an eBPF program to it,
which affects its performance. This document summarizes an experiment
we conducted to measure that impact.

## Testing environment

The experiment was conducted in a typical workstation environment
running Fedora Linux:

- Hardware: Intel Core i7-1185G7 @ 3.00GHz (4 cores, 8 threads), 32 GB memory
- OS: Fedora 38 with Linux kernel 6.4.11-200.fc38.x86_64

The following additional components were installed:

- crypto-auditing: commit b682180a92abb5abe98177f6e9045820bbdfcf01, built with io\_uring enabled
- gnutls: 3.8.0-9.fc39.1 from [COPR](https://copr.fedorainfracloud.org/coprs/ueno/crypto-auditing/)

## Testing scenarios

The TLS handshake benchmark
[program](https://gitlab.com/dueno/benchmark-handshake) can perform
TLS handshakes over an in-memory transport instead of sockets.

We used this program to perform TLS 1.3 handshakes 10000 times, using
all CPUs available to the operating system.

The following commands were used:

```console
$ sudo sysctl -w kernel.perf_event_paranoid=-1
$ perf stat ./benchmark-handshake -c 10000 -p $(nproc) --priority NORMAL
```

To measure the impact of context switches, where we expect
`crypto-auditing-agent` and the applications to compete for the
available CPU, we also emulated a single-CPU system with the kernel
parameter `nr_cpus=1`.

## Results

### Overall time spent

- With 8 CPUs, there is no visible difference in the overall time
  spent, regardless of whether `crypto-auditing-agent` attaches the
  eBPF program
- With a single CPU, the overall time spent increases by approximately
  4% when the benchmark program runs with `crypto-auditing-agent`
  enabled

### Context switches

- With 8 CPUs, 7.67 times more context switches are observed when
  `crypto-auditing-agent` is enabled
- With a single CPU, 3.69 times more context switches are observed
  when `crypto-auditing-agent` is enabled

### Interpretation

We currently conclude that the performance impact on the overall time
is negligible. This is mainly because the eBPF ring buffer is used
without any synchronization, and in user space the data is written to
disk asynchronously using io\_uring. This also means that some events
may be lost, depending on the configured size of the ring buffer.

Although more context switches are observed, they do not appear to
contribute much to the overall time. Since the benchmark program uses
an in-memory transport (and therefore makes no system calls or context
switches of its own) and involves no I/O operations, we expect the
relative impact to be even smaller in real-world applications.
