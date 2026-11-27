# Objectives and high-level design

<!-- toc -->
- [Summary](#summary)
- [Motivation](#motivation)
  - [Goals](#goals)
  - [Non-goals](#non-goals)
- [Proposal](#proposal)
  - [User stories](#user-stories)
    - [Gather Aggregated Statistics on TLS Cipher Suites](#gather-aggregated-statistics-on-tls-cipher-suites)
    - [Identify Specific Uses of SHA-1 in Signatures](#identify-specific-uses-of-sha-1-in-signatures)
    - [Identify Potentially Insecure Algorithms Used in an Organization](#identify-potentially-insecure-algorithms-used-in-an-organization)
  - [Risks and Mitigations](#risks-and-mitigations)
- [Design Details](#design-details)
  - [Architecture](#architecture)
  - [Collected information](#collected-information)
  - [Probes](#probes)
  - [Implementation notes](#implementation-notes)
  - [Prior art](#prior-art)
  - [Test Plan](#test-plan)
  - [Upgrade / Downgrade Strategy](#upgrade--downgrade-strategy)
- [Drawbacks](#drawbacks)
- [Alternatives](#alternatives)
<!-- /toc -->

## Summary

This project aims to build the infrastructure needed to audit
cryptographic operations performed by cryptographic libraries on a
system. This is achieved by instrumenting specific entry points in the
libraries used by user-space processes, and collecting data for later
analysis.

## Motivation

As security research advances, it is not uncommon for cryptographic
algorithms and protocols that were once considered secure to be found
vulnerable. To keep information systems secure by current standards,
the best practice is for local and organizational administrators to
ensure that their systems use only secure algorithms.

Fedora and RHEL provide a system-wide [mechanism][crypto-policies] to
enforce policies on which cryptographic algorithms are allowed on the
system. However, local administrators can relax the policy to
accommodate legacy applications, and the policies themselves need to
evolve over time to reflect advances in research.

Therefore, a mechanism is needed to audit the actual use of
cryptographic operations on systems.

### Goals

* Provide data to local system administrators who are analyzing the
  system configuration and behavior

* Provide data to a central collection party that can correlate and
  analyze data across multiple machines. This gives valuable insight
  into which algorithms are actually in use, so that informed
  decisions can be made about future policy.

### Non-goals

TBD

## Proposal

### User stories

The following user stories describe use cases that the crypto-auditing
project aims to address. They serve as input to design decisions.

#### Gather Aggregated Statistics on TLS Cipher Suites

When deciding on defaults for the entire distribution, it would be
helpful to estimate how many of our customers would be negatively
affected by stricter defaults. Mozilla faced a similar problem with
the Firefox browser, and implemented telemetry that provides
anonymized statistics on the [TLS versions] used and the [negotiated
cipher suites].

As a member of the crypto team and a maintainer of a cryptographic
library for RHEL, I want anonymized, aggregated statistics on TLS
versions, negotiated cipher suites, and other relevant details of TLS
handshakes (e.g., the asymmetric cryptosystem and key size), collected
from a consenting subset of our customers' machines, so that I can
make informed decisions about whether tightening the defaults further
would cause significant problems for our customers.

#### Identify Specific Uses of SHA-1 in Signatures

At Real World Crypto 2020 in New York, Leurent and Peyrin presented
"[SHA-1 is a Shambles]" ([paper][sha1-paper]), a new chosen-prefix
collision attack on SHA-1. The authors estimated the cost of the
attack at about USD 45k in 2020, projected to drop to USD 10k by
2025. Since chosen-prefix collisions make signatures forgeable, and
the authors demonstrated the attack on PGP key signatures, we should
collectively stop relying on signatures that use SHA-1 as the
digest. Crypto auditing should help with this by making uses of SHA-1
in signatures traceable.

Unfortunately, completely disabling SHA-1 is not an option, since it
is widely used for non-cryptographic purposes, e.g., as fingerprints
of TLS certificates.

As the maintainer of a package that uses signatures, or as a local
system administrator, I want to identify which processes on my system
use SHA-1 digests when creating or verifying signatures, so that I can
migrate them to a more modern digest algorithm. Once I have made these
changes, I want to be able to quickly confirm that SHA-1 is no longer
used in signatures.

#### Identify Potentially Insecure Algorithms Used in an Organization

Cryptography is constantly evolving, and new vulnerabilities are
discovered over time. Organizations are required – sometimes by law,
sometimes by standards they must comply with – to ensure that their
communication is secure, i.e., that it still uses algorithms
considered secure by the cryptographic community and/or auditors.

While RHEL's [crypto-policies] allow setting rules for which
algorithms are allowed by default, applications and users can
circumvent these defaults. Currently, there is no runtime monitoring
of the actual behavior of processes on the system.

As an organization administrator, I want an overview of the
cryptographic algorithms used at runtime by the machines under my
control, so that I can identify which processes on which machines use
old and potentially insecure protocols, possibly in violation of the
configured crypto policy, and may need attention or migration to newer
standards.

Red Hat Insights could serve as a front end for presenting this data.

### Risks and Mitigations

* We will modify cryptographic libraries, which will then need to
  maintain compatibility of the [probes](#probes). As the maintenance
  cost cannot be ignored, close and sustainable collaboration with the
  upstream communities is required.

* We need to make clear that this mechanism does not intentionally
  expose users to privacy risks. Although cryptographic operations are
  inherently applied to sensitive data, we should be mindful of any
  correlation between users' data or actions and cryptographic
  operations.

## Design Details

### Architecture

The overall architecture consists of the following components:
- Cryptographic libraries with probes enabled
- A collector agent, which receives probe events and stores them in a
  primary log file as quickly as possible
- Log consumers, which process the primary log further, e.g., by
  converting it into a format that Insights parsers can easily handle

### Collected information

While the types of information collected may vary, they should be
unambiguously classified by granularity. This proposal uses
indivisible cryptographic operations as the unit of monitoring, such
as [FIPS186-4] digital signature operations and [SP800-90A] random
number generation. This aligns the [probes](#probes) with the
existing FIPS 140-3 [service indicator implementations] in the
cryptographic libraries.

Any higher-level contextual information can be associated with these
operations as fields in [structured logging].

### Probes

For the agent to detect entry into cryptographic operations, the
monitored programs and the cryptographic libraries they depend on are
instrumented. This is typically done using [USDT] (user statically
defined tracepoints).

### Implementation notes

There are multiple ways to implement this architecture.

The simplest is to implement the collector agent and the log consumers
as a single monolithic process that interacts directly with the
running processes through probe points. This approach may keep the
collector process constantly busy, as it performs multiple tasks at
once.

A multi-process architecture could avoid this issue: the collector
agent would wake up only when probe events arrive, and the Insights
consumer would wake up only periodically. This, however, could incur
the cost of IPC between the components. A publish-subscribe model
similar to [MQTT] (Message Queuing Telemetry Transport) could benefit
both performance and flexibility.

### Prior art

[Network Observability] uses a similar eBPF-based architecture to
collect and aggregate all ingress and egress flows.

### Test Plan

TBD

### Upgrade / Downgrade Strategy

TBD

## Drawbacks

Trust in publishers: the architecture requires publishers to be
trustworthy, meaning that they always send correct information to the
broker. This could be ensured by applying standard Unix capabilities
and SELinux labels to the publisher process, possibly with support
from the kernel [IMA] (Integrity Measurement Architecture).

## Alternatives

Instead of a multi-process architecture, it is possible to provide a
set of CLI (command-line interface) tools that interact directly with
the monitored programs and process the collected data. However, this
setup would eventually become more complex than the multi-process
approach as new requirements (e.g., new types of subscribers) arise.

We could also use application-level information, such as TLS key
derivation, as the unit of events. This, however, makes it harder to
maintain compatibility of the probes as more applications and
protocols need to be supported.

[FIPS186-4]: https://csrc.nist.gov/publications/detail/fips/186/4/final
[IMA]: https://sourceforge.net/p/linux-ima/wiki/Home/
[MQTT]: https://mqtt.org
[Network Observability]: https://github.com/netobserv/netobserv-ebpf-agent
[SHA-1 is a Shambles]: https://sha-mbles.github.io/
[SP800-90A]: https://csrc.nist.gov/publications/detail/sp/800-90a/rev-1/final
[TLS versions]: https://telemetry.mozilla.org/new-pipeline/dist.html#!cumulative=0&end_date=2022-03-08&include_spill=0&keys=__none__!__none__!__none__&max_channel_version=nightly%252F99&measure=SSL_HANDSHAKE_VERSION&min_channel_version=null&processType=*&product=Firefox&sanitize=1&sort_by_value=0&sort_keys=submissions&start_date=2022-02-07&table=0&trim=1&use_submission_date=0
[USDT]: https://lwn.net/Articles/753601/
[crypto-policies]: https://gitlab.com/redhat-crypto/fedora-crypto-policies/
[negotiated cipher suites]: https://telemetry.mozilla.org/new-pipeline/dist.html#!cumulative=0&end_date=2022-03-08&include_spill=0&keys=__none__!__none__!__none__&max_channel_version=nightly%252F99&measure=SSL_CIPHER_SUITE_FULL&min_channel_version=null&processType=*&product=Firefox&sanitize=1&sort_by_value=0&sort_keys=submissions&start_date=2022-02-07&table=0&trim=1&use_submission_date=0
[service indicator implementations]: https://docs.google.com/document/d/1ePqdkYLVEFtoGkqr7gS1aBRnZRfoM-d2lbU5UgGGbhY/edit?usp=sharing
[sha1-paper]: https://eprint.iacr.org/2020/014.pdf
[structured logging]: https://www.freedesktop.org/software/systemd/man/systemd.journal-fields.html
