# Objectives and high-level design

<!-- toc -->
- [Summary](#summary)
- [Motivation](#motivation)
  - [Goals](#goals)
  - [Non-Goals](#non-goals)
- [Proposal](#proposal)
  - [User Stories](#user-stories-optional)
    - [Gather Aggregated Statistics on TLS Cipher Suites](#gather-aggregated-statistics-on-tls-cipher-suites)
    - [Identify Specific Uses of SHA-1 in Signatures](#identify-specific-uses-of-sha-1-in-signatures)
    - [Identify Potentially Insecure Algorithms Used in an Organization](#identify-potentially-insecure-algorithms-used-in-an-organization)
  - [Risks and Mitigations](#risks-and-mitigations)
- [Design Details](#design-details)
  - [Architecture](#architecture)
  - [Collected information](#collected-information)
  - [Probes](#probes)
  - [Test Plan](#test-plan)
  - [Upgrade / Downgrade Strategy](#upgrade--downgrade-strategy)
- [Drawbacks](#drawbacks)
- [Alternatives](#alternatives)
<!-- /toc -->

## Summary

This project aims to create the infrastructure needed to audit crypto
operations performed by crypto libraries on a system. This is
accomplished by instrumenting specific entry points in crypto
libraries, as they are used by user space processes on the system, and
collect data so that it can be analyzed later.

## Motivation

As security research advances, it is not uncommon that crypto
algorithms/protocols that were once considered secure are now known to
be vulnerable. To maintain the information systems to be secure
according to the current status quo, the best practice is for the
local and organizational administrators to ensure that the systems are
using only secure algorithms.

Fedora and RHEL provide a system-wide [mechanism](crypto-policies) to
enforce policies on which crypto algorithms are allowed on the
system. It is, however, possible for the local administrator to relax
the policy to work around legacy applications, as well as the policies
themselves need to evolve over time to reflect recent advances in
research.

Therefore, a mechanism is needed to audit the actual usage of crypto
operations on the systems.

### Goals

* Provide data to a local system administrator that is analyzing the
  system configuration/behavior

* Provide data to some central collection party that can then
  correlate/analyze data across multiple machines. This will provide
  valuable information on what is actually being used so that informed
  decisions can be made in terms of future policy.

### Non-goals

TBD

## Proposal

### User stories

The following user stories describe use cases that we want to be able
to solve with the crypto auditing project, and will be used as inputs
for design decisions.

#### Gather Aggregated Statistics on TLS Cipher Suites

When making decisions on defaults for the entire distribution, it
would be helpful to be able to judge how many of our customers will be
negatively impacted by tighter defaults. Mozilla has faced a similar
problem for their Firefox browser, and has implemented telemetry that
gives them anonymized statistics on the used [TLS versions] and
[negotiated cipher suites].

As a member of the crypto team and maintainer of a crypto library for RHEL, I want anonymized aggregated statistics on the TLS version, negotiated cipher suites and other relevant details of a TLS handshake (e.g., asymmetric cryptosystem, key size), collected from a consenting subset of our customers’ machines, so that I can take informed decisions on whether tightening the defaults further will cause our customers big problems or not.

#### Identify Specific Uses of SHA-1 in Signatures

At Real World Crypto 2020 in Singapore, Leurent and Peyrin presented
“[SHA-1 is a Shambles]” ([paper][sha1-paper]), a new chosen-prefix collision
attack. The authors estimate the attack cost at about 45k USD in 2020,
with a projection of 10k USD in 2025. Since chosen-prefix collisions
make signatures vulnerable, and the authors presented the attack with
a signature on PGP keys, we should collectively stop relying on
signatures that use SHA-1 as digest. Crypto auditing should help with
this by making the use of SHA-1 in signatures traceable.

Completely disabling the SHA-1 algorithm is unfortunately not an
option, since it is widely used for non-cryptographic purposes, e.g.,
as a fingerprint for TLS certificates.

As a package maintainer of a package that uses signatures, or as a
local system administrator, I want to identify which processes on my
system use SHA-1 digests in signature verification or creation so that
I can make the necessary changes to a more modern digest
algorithm. Once I made these changes, I want to be able to quickly
confirm that the use of SHA-1 in digests has stopped.

#### Identify Potentially Insecure Algorithms Used in an Organization

The state of cryptography is constantly evolving, and new
vulnerabilities are discovered over time. Organizations are required –
sometimes legally, sometimes through standards with which they must
comply – to ensure that their communication is secure, i.e., is still
using algorithms considered secure by the cryptographic community
and/or auditors.

While RHEL’s [crypto-policies] allow setting rules as to which
algorithms are allowed by default, applications and users can work
around these defaults. No runtime monitoring of the actual behavior of
processes on the system currently exists.

As an organization administrator, I want an overview of cryptographic
algorithms used by machines under my control at runtime, so that I can
identify which processes on which machines use old and potentially
insecure protocols, potentially in violation of the configured crypto
policy, and may need attention and migration to newer standards.

Red Hat Insights may be a potential front-end to show this data.

### Risks and Mitigations

* We will modify the crypto libraries and force them to maintain the
  compatibility of the [probes](#probes). As the cost of maintenance
  can't be ignored, close and sustainable collaboration with the
  upstream communities is required.

* We will need to be clear that this mechanism does not intentionally
  face users to privacy risks. Although crypto operations are
  inherently applied to sensitive data, we should be mindful of any
  correlations between users' data/actions and crypto operations.

## Design Details

### Architecture

The entire architecture consists of multiple components:
- The cryptographic libraries with probes enabled
- The collector agent which receives probe events and store them in a
  primary log file as fast as possible
- The log consumers that processes the primary log for further
  processing, e.g., store them in a format Insights parsers can easily
  handle

### Collected information

While the types of the information being collected may vary, they
should be unambiguously classfied by granularity.  This proposal
suggests using inseparable crypto operations as a unit of monitoring,
such as [FIPS186-4] digital-signature operations and [SP800-90A]
random number generation.  This aligns the [probes](#probes) to the
existing FIPS140-3 [service indicator implementations] in the crypto
libraries.

Any higher level contextual information can be associated to those
operations as a field in [structured logging].

### Probes

For the agent to detect any entry to the crypto operations, the
monitored programs and the dependent crypto libraries are
instrumented. This can be typically done using [USDT] (user statically
defined tracepoints).

### Implementation notes

There can be multiple ways of implementing the architecture.

The simplest form would be that the collector agent and log consumers
are implemented as a single monolithic process and directly interact
with the running processes through probe points. This approach may
require the collector process to be always busy as it does multiple
tasks at the same time.

Adopting a multi-process architecture could avoid the issue: the
collector agent could be woken up only when probe events arrive and
the Insight consumer could be woken up only periodically.  This,
however, could impose a cost of IPC between the components.  A
publisher-subscriber model similar to [MQTT] (Message Queuing
Telemetry Transport) could be beneficial to performance and
flexibility.

### Prior art

[Network Observability] uses a similar architecture for collecting and
aggregating all the ingress and egress flows, using eBPF.

### Test Plan

TBD

### Upgrade / Downgrade Strategy

TBD

## Drawbacks

Trust of the publisher: The architecture requires that the publishers
are trustworthy, meaning that they always send correct information to
the broker. This could be done using the standard Unix capabilities
with SELinux labels to the publisher process, possibly with kernel
[IMA] (integrity measurement architecture) support.

## Alternatives

Instead of imposing a multi-process architecture, it is possible to
provide a set of CLI (command-line interface) tools that directly
interact with the monitored programs and process the collected
data. This setup, however, would be eventually more complex than the
multi-process approach when any new requirements (e.g., new types of
subscribers) arise.

We could base on application level information, such as TLS key
derivation, as a unit of events. This, however, makes it harder to
maintain the compatibility of the probes as we need to support more
applications/protocols.

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
