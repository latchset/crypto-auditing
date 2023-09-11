# Measuring performance impact

## Summary

The applications being audited are attached an eBPF program, which
impacts performance. We conducted an experiment to measure
performance, which this document tries to summarize.

## Testing environment

The experiment was conducted on a typical workstation environment
running Fedora Linux:

- Hardware: Intel Core i7-1185G7 @ 3.00GHz, 8 core CPU, 32GB memory
- OS: Fedora 38 with Linux kernel 6.4.11-200.fc38.x86_64

The following additional components were installed:

- crypto-auditing: b682180a92abb5abe98177f6e9045820bbdfcf01 checkout, built with io\_uring enabled
- gnutls: 3.8.0-9.fc39.1 from [COPR](https://copr.fedorainfracloud.org/coprs/ueno/crypto-auditing/)

## Testing scenarios

The TLS handshake benchmark
[program](https://gitlab.com/dueno/benchmark-handshake) is capable of
performing TLS handshake on a memory-based transport instead of
sockets.

We use this program to perform TLS 1.3 handshake 10000 times,
utilizing all CPU cores available to the operating system.

The following commands were used:

```console
$ sudo sysctl -w kernel.perf_event_paranoid=-1
$ perf stat ./benchmark-handshake -c 10000 -p $(nproc) --priority NORMAL
```

To measure the impact of context switches, where we expect
`crypto-auditing-agent` and the applications to contend each other
with the available CPU, we emulated a single core system with the
kernel parameter `nr_cpus=1`.

## Results

### Overall time spent

- When running with 8 cores, there is no visible difference in overall
  time spent, regardless of `crypto-auditing-agent` attaching eBPF
  program
- When running with a single core, there is approximately 4%
  degradation in overall time spent, when running the benchmark
  program with `crypto-auditing-agent` enabled

### Context switches

- When running with 8 cores, there are 7.67 times more context
  switches observed when `crypto-auditing-agent` is enabled
- When running on a single core, there are 3.69 times more context
  switches when `crypto-auditing-agent` is enabled.

### Interpretation

We currently conclude the performance impact is negligible in terms of
overall time.  This is mainly because we use eBPF ringbuffer without
any synchronization, and in userspace the data is also asynchronously
written to disk using io\_uring.  That means that some events might be
missed, depending on the configured size of ringbuffer.

While there are a number of context switches observed, they don't seem
to contribute much to the overall time spent.  As the benchmark
program uses the memory-based transport (and therefore, no system
calls and no context switches) and no I/O operations are involved, we
expect that the performance impact would be more negligible in
practical applications.
