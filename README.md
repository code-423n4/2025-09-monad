# Monad audit details
- Total Prize Pool: $504,000 in USDC
  - Warden pool: $500,000 in USDC
    - HM awards: $480,000 in USDC 
    - QA awards: $20,000 in USDC
  - Judge awards: $3,500 in USDC
  - Scout awards: $500 in USDC
- [Read our guidelines for more details](https://docs.code4rena.com/competitions)
- Starts September 15, 2025 20:00 UTC 
- Ends October 12, 2025 20:00 UTC

**❗ Important notes for wardens** 

1. If no valid Highs or Mediums are found, the full award pool will be distributed among A- and B-grade QA reports, The submission criteria for QA reports can be viewed [here](https://docs.code4rena.com/competitions/submission-guidelines#qa-reports-low-governance).
2. While this audit's code is not yet deployed, a variation of the ["live criticals" exception](https://docs.code4rena.com/awarding#the-live-criticals-exception) will apply:
  - Sponsors may choose to fix High-severity findings during the submission phase of the audit. 
  - Wardens are encouraged to submit High-severity submissions promptly, to guarantee payout in the case where [a sponsor patches a finding during the audit](https://docs.code4rena.com/awarding#the-live-criticals-exception).
  - If a fix is planned, C4 staff will post a notification for wardens in the audit channel, to provide as much advance notice as possible and encourage wardens to submit any in-progress work.
  - Once the fix has been applied, it will be added to the `Publicly Known Issues` section.
3. Prior to receiving payment for this audit, you MUST become a [Certified Contributor](https://docs.code4rena.com/roles/sr-wardens#certified-contributors) (successfully complete KYC).
  - You do not have to be certified prior to submitting bugs, but you must successfully complete the certification process within 30 days of the award announcement in order to receive awards. 
  - This applies to all audit participants including wardens, teams, judges and scouts.
  - C4 staff will contact all relevant participants after awards are announced, to assist with this process.
4. Judging phase risk adjustments (upgrades/downgrades):
  - High- or Medium-risk submissions downgraded by the judge to Low-risk (QA) will be ineligible for awards.
  - Upgrading a Low-risk finding from a QA report to a Medium- or High-risk finding is not supported.
  - As such, wardens are encouraged to select the appropriate risk level carefully during the submission phase.

## Automated Findings / Publicly Known Issues
 
_Note for C4 wardens: Anything included in this `Automated Findings / Publicly Known Issues` section is considered a publicly known issue and is ineligible for awards._

The following issues and risks are considered **known** or **by design** and will not be considered valid findings in this contest.

- Block policy discounts gas price by incorrectly applying EIP-1559 to legacy transactions (C4 staff note: this issue was addressed by a public [PR](https://github.com/category-labs/monad-bft/pull/2386) on September 25, 2025 at 18:30 UTC; therefore all submissions of this finding after that timestamp will be considered out of scope.)
- Reserve balance checks were not applied consistently to create transactions, e.g. CREATE / CREATE2 (C4 staff note: there was a public PR originally created to address this issue on September 16, 2025 at 15:38 UTC; therefore all submissions related to this finding after that timestamp will be considered out of scope.)
- Duplicated validation logic for EIP-7702 authorization lists. (C4 staff note: this issue was addressed by a public [PR](https://github.com/category-labs/monad-bft/pull/2365))
- 2025-09-28, 15:20 UTC: Monad `testnet-2` crashed due to a bug at 2025-09-27 09:23 UTC. The description of the bug is as follows: 
    > Execution enforces that the reserve balance is protected by examining the balances before and after transaction execution and making a decision on whether or not to revert that transaction. The current implementation of reserve balance is missing adjustments for relaxed merge.
    - `testnet-2` was recovered by [disabling relaxed merge](https://github.com/category-labs/monad/pull/1735) while a more tailored fix is pending. This bug will be considered out of scope from the time of the crash and for the remainder of the audit competition. Any other findings related to relaxed merge (i.e. outside of this interaction with reserve balance) are still in scope.
    - This `README` will be updated again once the issue has been addressed in full.
- Nonce overflow check in block validator (C4 staff note: this issue was addressed by a public [PR](https://github.com/category-labs/monad-bft/pull/2388).)

### General Risks

- **Attacks on the Consensus Trust Model:** The security of the Monad protocol relies on a fundamental assumption of a supermajority of stake weight being non-faulty. Therefore, any attack scenario requiring more than 1/3 of the network's stake to be malicious is considered a fundamental, out-of-scope attack on the protocol's trust model and will not be considered a valid finding. This includes, but is not limited to, scenarios resulting in network finality failures, double-spending, or long-range attacks.
- **Validator/Proposer Malicious Behavior:** Reports related to attack scenarios by a malicious validator or proposer that are not economically rational - i.e. where the attacker cannot profit or the attack would cost more than any potential profit - are out of scope.
- **Naive Attacks on Cryptographic Primitives:** The utilized cryptographic primitives were selected due to their widely accepted hardness. Attacks requiring their breakage are out of scope unless they provide clear indices how the utilized algorithm outperforms existing attacks.
- **Validator/Stake Centralization:** This is an inherent social and economic dynamic of a PoS system, not a protocol bug.
- **Transaction Censorship:** The theoretical collusion of a small number of malicious validators to censor transactions is an acceptable risk and is addressed by social and economic countermeasures, not as a protocol vulnerability.
- **Economic Attacks:** Any attack that relies on an attacker spending a prohibitively high amount of gas or network resources (e.g., gas price manipulation or DoS via gas griefing) is considered an acceptable economic attack and is out of scope.
- **Insecure and/or Inappropriate Node Configuration:** Findings related to improperly configured nodes are considered out of scope, as it is the node operator's responsibility to ensure correct setup.
- **Open Issues:** Any open issues in our public trackers at the start of the contest are considered known risks and will not constitute a valid finding.
- **Reporting and Performance Metrics:** Telemetry and performance reporting failures are out of scope for bug reports, unless they enable a severe vulnerability like remote code execution (RCE) or a consensus node crash on a default configuration.
  - These reports will only be considered in scope for QA submissions.
- **General DDoS attacks:** such as amplification, reflection, or flooding, that impact node or network availability but do not exploit protocol- or implementation-specific weaknesses.
- **UI/UX Security:** Security-related bugs in the user interface or user experience, such as sensitive information in logs or password brute force vulnerabilities, are out of scope as this contest is focused on the core protocol's security.
- **Insecure Dependencies:** Findings concerning insecure dependencies with known vulnerabilities are out of scope. The contest is focused on the custom Monad protocol code, not third-party libraries.
- **Missing Best Practices:** Findings related to missing general security best practices for API endpoints, such as the lack of security flags for HTTP-based APIs or rate limiting, are out of scope.
- **Social Engineering:** Any attack that relies on social engineering is out of scope and will not be considered a valid finding.
- **Physical Attacks:** Any attack that requires physical access to a node or its hardware is out of scope. This contest is limited to the security of the Monad protocol's software implementation.
- **Local attacks against nodes:** Any attack against the software running on a node that requires the attacker to have prior access to that node. This contest focuses on attacks that are possible against the components exposed over the network.
- **Missing Optimisations:** Findings that present a potential performance improvement in client code are out of scope, unless that improvement mitigates a viable attack scenario.
- **C/C++ Undefined Behavior:** Findings related to C/C++ undefined behavior are considered low severity unless a practical, demonstrable impact can be shown in a node’s default configuration. The mere existence of undefined behavior, without a clear and practical exploit, will not be considered a higher than low severity finding.

### Monad-Specific 

- **EVM/EIP Deviation**:
  - **Gas Limit & Gas Pricing:** Monad's gas limit and gas pricing model do not strictly follow Ethereum's EIPs (such as EIP-1559). Any finding related to these intended deviations is out of scope, unless the issue can be used to achieve a form of DoS.
  - **Max Contract Size:** The maximum contract size is 128 KB, which is larger than Ethereum's 24.5 KB limit. This is by design and is not considered a bug.
  - **Mempool:** There is no global mempool. Transactions are forwarded directly to a subset of future leaders. Any findings based on the assumption of a global mempool or the assumption of private mempool access are considered out of scope.
  - **Historical Data:** Full nodes do not store arbitrary historical state due to high throughput and storage requirements. Reports related to the inability to access full historical state from a standard full node are out of scope.
  - **VM Execution Trace & Error Codes:** Due to natural constraints of JIT execution, the execution trace and, therefore, EVM error codes of the VM (while executing via JIT compilation) are not guaranteed to be the exact same as major interpreted EVM implementations. Reports related to this are out of scope.
- **RPC Compliance:** The RPC is designed to be generally Ethereum-compliant but may have minor deviations due to Monad's unique adaptations. Reports on these deviations will not be considered valid findings.
  - See intentional differences:
    - https://docs.monad.xyz/reference/
- **Statesync Peer Trust Model:** Statesync peers are assumed to be trusted. Findings demonstrating a malicious statesync peer are therefore out of scope.
- **Hardware and Operating System Performance:** Monad is a high-performance system designed to run on specific hardware and operating system requirements. Any performance degradation, synchronization issues, or consensus failures that result from a node operating on hardware or an operating system below the recommended specifications are considered out of scope. The security and performance model assumes that node operators will meet or exceed the minimum hardware and operating system requirements outlined in the official documentation.
- **RaptorCast protocol DoS:** findings that rely solely on exhausting cryptographic computation in the RaptorCast transport (e.g., forcing excessive handshakes or signature verifications) and do not exploit a protocol- or implementation-specific flaw are also out of scope.
- **Attacks requiring an infeasible amount of MON:** MON (Monad’s native token) issuance will be limited and therefore reports requiring large amounts of MON (in the ranges of `type(uint256).max`) are not in scope.
- **Slashing:** findings related to malicious validator behavior that would be mitigated by slashing is not in scope.

### Existing issues

Any GitHub issues raised prior to the start of the audit contest found in the following two repos are considered out of scope. This also applies to any newly discovered vulnerabilities that are a direct result of the same underlying root cause as a known, open issue.

- https://github.com/category-labs/monad-bft/issues
- https://github.com/category-labs/monad/issues

# Overview

Monad is a high-performance Ethereum-compatible L1. Monad materially advances the efficient frontier in the balance between decentralization and scalability.

This repo contains 2 main folders:

## Monad

Contains the execution component of a Monad node. It handles the transaction processing for new blocks, and keeps track of
the state of the blockchain. Consequently, this repository contains the source code for Category Labs' custom [EVM implementation](https://docs.monad.xyz/monad-arch/execution/native-compilation), its [database implementation](https://docs.monad.xyz/monad-arch/execution/monaddb), and the high-level [transaction scheduling](https://docs.monad.xyz/monad-arch/execution/parallel-execution).


## BFT
Contains the Monad consensus client and JsonRpc server. Monad consensus collects transactions and produces blocks which are written to a ledger filestream. These blocks are consumed by Monad execution, which then updates the state of the blockchain. The [triedb](https://github.com/code-423n4/2025-09-monad/blob/main/bft/monad-triedb/README.md) is a database which stores block information and the blockchain state.

## Links

- **Previous audits:** previously audited by Zellic and Spearbit, reports being finalized.
- **Documentation:** https://docs.monad.xyz
- **Website:** https://www.monad.xyz
- **X/Twitter:** https://x.com/monad

### Code walk-throughs

1. [Consensus](https://youtu.be/SnGXl0ejCy4)
2. [Execution](https://youtu.be/funlv0idZL0)
3. [Networking](https://youtu.be/moW3GELFeR8) 

---

# Scope


### Files in scope

| filename                                                                     | code   |
|------------------------------------------------------------------------------|--------|
| ./bft/monad-block-persist/src/lib.rs                                         |    201 |
| ./bft/monad-blocksync/src/blocksync.rs                                       |   1895 |
| ./bft/monad-blocksync/src/lib.rs                                             |      2 |
| ./bft/monad-blocksync/src/messages/message.rs                                |    271 |
| ./bft/monad-blocksync/src/messages/mod.rs                                    |      1 |
| ./bft/monad-blocktree/src/blocktree.rs                                       |   1499 |
| ./bft/monad-blocktree/src/lib.rs                                             |      2 |
| ./bft/monad-blocktree/src/tree.rs                                            |    264 |
| ./bft/monad-bls/benches/bls.rs                                               |     97 |
| ./bft/monad-bls/src/aggregation_tree.rs                                      |    800 |
| ./bft/monad-bls/src/bls.rs                                                   |    923 |
| ./bft/monad-bls/src/lib.rs                                                   |    129 |
| ./bft/monad-chain-config/src/execution_revision.rs                           |     52 |
| ./bft/monad-chain-config/src/lib.rs                                          |    246 |
| ./bft/monad-chain-config/src/revision.rs                                     |     83 |
| ./bft/monad-consensus-state/src/command.rs                                   |    154 |
| ./bft/monad-consensus-state/src/lib.rs                                       |   4423 |
| ./bft/monad-consensus-state/src/timestamp.rs                                 |    117 |
| ./bft/monad-consensus-types/src/block_validator.rs                           |     86 |
| ./bft/monad-consensus-types/src/block.rs                                     |    741 |
| ./bft/monad-consensus-types/src/bls.rs                                       |      0 |
| ./bft/monad-consensus-types/src/checkpoint.rs                                |     33 |
| ./bft/monad-consensus-types/src/lib.rs                                       |     98 |
| ./bft/monad-consensus-types/src/metrics.rs                                   |    149 |
| ./bft/monad-consensus-types/src/no_endorsement.rs                            |     58 |
| ./bft/monad-consensus-types/src/payload.rs                                   |     91 |
| ./bft/monad-consensus-types/src/quorum_certificate.rs                        |    110 |
| ./bft/monad-consensus-types/src/timeout.rs                                   |    366 |
| ./bft/monad-consensus-types/src/tip.rs                                       |     81 |
| ./bft/monad-consensus-types/src/validation.rs                                |     14 |
| ./bft/monad-consensus-types/src/validator_data.rs                            |    189 |
| ./bft/monad-consensus-types/src/voting.rs                                    |     27 |
| ./bft/monad-consensus/src/lib.rs                                             |      5 |
| ./bft/monad-consensus/src/messages/consensus_message.rs                      |    161 |
| ./bft/monad-consensus/src/messages/message.rs                                |    290 |
| ./bft/monad-consensus/src/messages/mod.rs                                    |      2 |
| ./bft/monad-consensus/src/no_endorsement_state.rs                            |    161 |
| ./bft/monad-consensus/src/pacemaker.rs                                       |    740 |
| ./bft/monad-consensus/src/validation/certificate_cache.rs                    |    186 |
| ./bft/monad-consensus/src/validation/mod.rs                                  |      3 |
| ./bft/monad-consensus/src/validation/safety.rs                               |    150 |
| ./bft/monad-consensus/src/validation/signing.rs                              |   1813 |
| ./bft/monad-consensus/src/vote_state.rs                                      |    410 |
| ./bft/monad-crypto/benches/hasher_bench.rs                                   |     46 |
| ./bft/monad-crypto/src/certificate_signature.rs                              |    211 |
| ./bft/monad-crypto/src/hasher.rs                                             |    103 |
| ./bft/monad-crypto/src/lib.rs                                                |     32 |
| ./bft/monad-crypto/src/signing_domain.rs                                     |     56 |
| ./bft/monad-dataplane/examples/node.rs                                       |     99 |
| ./bft/monad-dataplane/src/addrlist.rs                                        |    235 |
| ./bft/monad-dataplane/src/ban_expiry.rs                                      |    149 |
| ./bft/monad-dataplane/src/buffer_ext.rs                                      |     36 |
| ./bft/monad-dataplane/src/lib.rs                                             |    522 |
| ./bft/monad-dataplane/src/tcp/mod.rs                                         |    287 |
| ./bft/monad-dataplane/src/tcp/rx.rs                                          |    383 |
| ./bft/monad-dataplane/src/tcp/tx.rs                                          |    307 |
| ./bft/monad-dataplane/src/udp.rs                                             |    264 |
| ./bft/monad-eth-block-policy/src/lib.rs                                      |   3040 |
| ./bft/monad-eth-block-policy/src/nonce_usage.rs                              |    241 |
| ./bft/monad-eth-block-policy/src/validation.rs                               |    476 |
| ./bft/monad-eth-block-validator/src/lib.rs                                   |   1007 |
| ./bft/monad-eth-txpool-executor/src/forward.rs                               |    405 |
| ./bft/monad-eth-txpool-executor/src/ipc/config.rs                            |      7 |
| ./bft/monad-eth-txpool-executor/src/ipc/mod.rs                               |    122 |
| ./bft/monad-eth-txpool-executor/src/lib.rs                                   |    544 |
| ./bft/monad-eth-txpool-executor/src/metrics.rs                               |     27 |
| ./bft/monad-eth-txpool-executor/src/preload.rs                               |    329 |
| ./bft/monad-eth-txpool-executor/src/reset.rs                                 |     32 |
| ./bft/monad-eth-txpool-ipc/src/lib.rs                                        |    151 |
| ./bft/monad-eth-txpool-types/src/lib.rs                                      |     91 |
| ./bft/monad-eth-txpool/benches/common/controller.rs                          |    184 |
| ./bft/monad-eth-txpool/benches/common/mod.rs                                 |    104 |
| ./bft/monad-eth-txpool/benches/create_proposal.rs                            |     58 |
| ./bft/monad-eth-txpool/benches/insert.rs                                     |     49 |
| ./bft/monad-eth-txpool/benches/update.rs                                     |     53 |
| ./bft/monad-eth-txpool/src/event_tracker.rs                                  |    335 |
| ./bft/monad-eth-txpool/src/lib.rs                                            |      4 |
| ./bft/monad-eth-txpool/src/metrics.rs                                        |    121 |
| ./bft/monad-eth-txpool/src/pool/mod.rs                                       |    505 |
| ./bft/monad-eth-txpool/src/pool/pending/list.rs                              |     90 |
| ./bft/monad-eth-txpool/src/pool/pending/mod.rs                               |    120 |
| ./bft/monad-eth-txpool/src/pool/tracked/list.rs                              |    186 |
| ./bft/monad-eth-txpool/src/pool/tracked/mod.rs                               |    382 |
| ./bft/monad-eth-txpool/src/pool/tracked/sequencer.rs                         |    267 |
| ./bft/monad-eth-txpool/src/pool/transaction.rs                               |    213 |
| ./bft/monad-eth-types/src/lib.rs                                             |    293 |
| ./bft/monad-eth-types/src/serde/mod.rs                                       |     39 |
| ./bft/monad-ethcall/build.rs                                                 |     20 |
| ./bft/monad-ethcall/src/lib.rs                                               |    405 |
| ./bft/monad-executor-glue/benches/rlp_bench.rs                               |     58 |
| ./bft/monad-executor-glue/src/lib.rs                                         |   2168 |
| ./bft/monad-executor/src/lib.rs                                              |     38 |
| ./bft/monad-executor/src/metrics.rs                                          |     45 |
| ./bft/monad-executor/src/timed_event.rs                                      |     36 |
| ./bft/monad-ledger/src/lib.rs                                                |    234 |
| ./bft/monad-merkle/src/lib.rs                                                |    135 |
| ./bft/monad-node-config/examples/linter.rs                                   |     84 |
| ./bft/monad-node-config/src/bootstrap.rs                                     |     28 |
| ./bft/monad-node-config/src/fullnode_raptorcast.rs                           |     29 |
| ./bft/monad-node-config/src/fullnode.rs                                      |     17 |
| ./bft/monad-node-config/src/lib.rs                                           |     56 |
| ./bft/monad-node-config/src/network.rs                                       |     45 |
| ./bft/monad-node-config/src/peers.rs                                         |     19 |
| ./bft/monad-node-config/src/sync_peers.rs                                    |     23 |
| ./bft/monad-node/examples/ledger-tail.rs                                     |    257 |
| ./bft/monad-node/src/cli.rs                                                  |     46 |
| ./bft/monad-node/src/error.rs                                                |     59 |
| ./bft/monad-node/src/main.rs                                                 |    739 |
| ./bft/monad-node/src/state.rs                                                |    148 |
| ./bft/monad-peer-discovery/examples/sign-name-record.rs                      |     53 |
| ./bft/monad-peer-discovery/src/discovery.rs                                  |   1846 |
| ./bft/monad-peer-discovery/src/driver.rs                                     |    290 |
| ./bft/monad-peer-discovery/src/lib.rs                                        |    306 |
| ./bft/monad-peer-discovery/src/message.rs                                    |    142 |
| ./bft/monad-peer-discovery/src/mock.rs                                       |    207 |
| ./bft/monad-raptor/src/binary_search.rs                                      |     43 |
| ./bft/monad-raptor/src/lib.rs                                                |     12 |
| ./bft/monad-raptor/src/matrix/dense_matrix.rs                                |     63 |
| ./bft/monad-raptor/src/matrix/gaussian.rs                                    |    101 |
| ./bft/monad-raptor/src/matrix/invert.rs                                      |      6 |
| ./bft/monad-raptor/src/matrix/mod.rs                                         |      9 |
| ./bft/monad-raptor/src/matrix/rc_permutation.rs                              |     53 |
| ./bft/monad-raptor/src/matrix/rc_swap_matrix.rs                              |     66 |
| ./bft/monad-raptor/src/matrix/row_operation.rs                               |      4 |
| ./bft/monad-raptor/src/ordered_set.rs                                        |    108 |
| ./bft/monad-raptor/src/r10/a.rs                                              |     27 |
| ./bft/monad-raptor/src/r10/degree.rs                                         |     14 |
| ./bft/monad-raptor/src/r10/half.rs                                           |     22 |
| ./bft/monad-raptor/src/r10/ldpc.rs                                           |     19 |
| ./bft/monad-raptor/src/r10/lt.rs                                             |     52 |
| ./bft/monad-raptor/src/r10/matrix.rs                                         |     14 |
| ./bft/monad-raptor/src/r10/mod.rs                                            |     13 |
| ./bft/monad-raptor/src/r10/nonsystematic/decoder/buffer_id.rs                |     19 |
| ./bft/monad-raptor/src/r10/nonsystematic/decoder/buffer_state.rs             |     30 |
| ./bft/monad-raptor/src/r10/nonsystematic/decoder/buffer_weight_map.rs        |    211 |
| ./bft/monad-raptor/src/r10/nonsystematic/decoder/buffer.rs                   |     44 |
| ./bft/monad-raptor/src/r10/nonsystematic/decoder/check.rs                    |    155 |
| ./bft/monad-raptor/src/r10/nonsystematic/decoder/decode_finished.rs          |     24 |
| ./bft/monad-raptor/src/r10/nonsystematic/decoder/decode_inactivate.rs        |     24 |
| ./bft/monad-raptor/src/r10/nonsystematic/decoder/decode_inactive_gaussian.rs |     94 |
| ./bft/monad-raptor/src/r10/nonsystematic/decoder/decode_peel.rs              |     64 |
| ./bft/monad-raptor/src/r10/nonsystematic/decoder/decode_reactivate.rs        |     62 |
| ./bft/monad-raptor/src/r10/nonsystematic/decoder/decode.rs                   |    105 |
| ./bft/monad-raptor/src/r10/nonsystematic/decoder/init.rs                     |     81 |
| ./bft/monad-raptor/src/r10/nonsystematic/decoder/intermediate_symbol.rs      |    121 |
| ./bft/monad-raptor/src/r10/nonsystematic/decoder/managed_decoder.rs          |    123 |
| ./bft/monad-raptor/src/r10/nonsystematic/decoder/mod.rs                      |     43 |
| ./bft/monad-raptor/src/r10/nonsystematic/decoder/receive_symbol.rs           |     59 |
| ./bft/monad-raptor/src/r10/nonsystematic/encoder.rs                          |    157 |
| ./bft/monad-raptor/src/r10/nonsystematic/mod.rs                              |      2 |
| ./bft/monad-raptor/src/r10/parameters.rs                                     |    252 |
| ./bft/monad-raptor/src/r10/rand.rs                                           |     75 |
| ./bft/monad-raptor/src/r10/systematic_index.rs                               |    436 |
| ./bft/monad-raptor/src/xor_eq.rs                                             |     63 |
| ./bft/monad-raptorcast/benches/raptor_bench.rs                               |    141 |
| ./bft/monad-raptorcast/examples/service.rs                                   |    215 |
| ./bft/monad-raptorcast/src/config.rs                                         |    136 |
| ./bft/monad-raptorcast/src/lib.rs                                            |    845 |
| ./bft/monad-raptorcast/src/message.rs                                        |    422 |
| ./bft/monad-raptorcast/src/raptorcast_secondary/client.rs                    |    447 |
| ./bft/monad-raptorcast/src/raptorcast_secondary/group_message.rs             |    177 |
| ./bft/monad-raptorcast/src/raptorcast_secondary/mod.rs                       |    461 |
| ./bft/monad-raptorcast/src/raptorcast_secondary/publisher.rs                 |   1503 |
| ./bft/monad-raptorcast/src/udp.rs                                            |   1330 |
| ./bft/monad-raptorcast/src/util.rs                                           |    744 |
| ./bft/monad-rpc/benches/serialize.rs                                         |     92 |
| ./bft/monad-rpc/bin/docs.rs                                                  |      7 |
| ./bft/monad-rpc/build.rs                                                     |     10 |
| ./bft/monad-rpc/examples/benchmark.rs                                        |     45 |
| ./bft/monad-rpc/monad-rpc-docs/monad-rpc-docs-derive/src/lib.rs              |    238 |
| ./bft/monad-rpc/monad-rpc-docs/src/lib.rs                                    |    137 |
| ./bft/monad-rpc/src/chainstate/buffer.rs                                     |    179 |
| ./bft/monad-rpc/src/chainstate/mod.rs                                        |   1072 |
| ./bft/monad-rpc/src/cli.rs                                                   |    104 |
| ./bft/monad-rpc/src/comparator.rs                                            |     72 |
| ./bft/monad-rpc/src/docs.rs                                                  |     72 |
| ./bft/monad-rpc/src/eth_json_types.rs                                        |    494 |
| ./bft/monad-rpc/src/event/client.rs                                          |     28 |
| ./bft/monad-rpc/src/event/events.rs                                          |     23 |
| ./bft/monad-rpc/src/event/mod.rs                                             |      9 |
| ./bft/monad-rpc/src/event/server.rs                                          |    334 |
| ./bft/monad-rpc/src/handlers/debug.rs                                        |    693 |
| ./bft/monad-rpc/src/handlers/eth/account.rs                                  |    176 |
| ./bft/monad-rpc/src/handlers/eth/block.rs                                    |    206 |
| ./bft/monad-rpc/src/handlers/eth/call.rs                                     |   1014 |
| ./bft/monad-rpc/src/handlers/eth/gas.rs                                      |    493 |
| ./bft/monad-rpc/src/handlers/eth/mod.rs                                      |      5 |
| ./bft/monad-rpc/src/handlers/eth/txn.rs                                      |    370 |
| ./bft/monad-rpc/src/handlers/meta.rs                                         |     10 |
| ./bft/monad-rpc/src/handlers/mod.rs                                          |    809 |
| ./bft/monad-rpc/src/handlers/resources.rs                                    |    109 |
| ./bft/monad-rpc/src/hex.rs                                                   |    117 |
| ./bft/monad-rpc/src/jsonrpc.rs                                               |    413 |
| ./bft/monad-rpc/src/lib.rs                                                   |     15 |
| ./bft/monad-rpc/src/main.rs                                                  |    584 |
| ./bft/monad-rpc/src/metrics.rs                                               |    157 |
| ./bft/monad-rpc/src/serialize.rs                                             |     80 |
| ./bft/monad-rpc/src/timing.rs                                                |    109 |
| ./bft/monad-rpc/src/txpool/client.rs                                         |     50 |
| ./bft/monad-rpc/src/txpool/handle.rs                                         |     24 |
| ./bft/monad-rpc/src/txpool/mod.rs                                            |    173 |
| ./bft/monad-rpc/src/txpool/socket.rs                                         |     74 |
| ./bft/monad-rpc/src/txpool/state.rs                                          |    568 |
| ./bft/monad-rpc/src/txpool/types.rs                                          |     10 |
| ./bft/monad-rpc/src/vpool.rs                                                 |     76 |
| ./bft/monad-rpc/src/websocket/handler.rs                                     |    821 |
| ./bft/monad-rpc/src/websocket/mod.rs                                         |      1 |
| ./bft/monad-secp/benches/secp.rs                                             |    116 |
| ./bft/monad-secp/src/lib.rs                                                  |    164 |
| ./bft/monad-secp/src/recoverable_address.rs                                  |    188 |
| ./bft/monad-secp/src/secp.rs                                                 |    332 |
| ./bft/monad-state-backend/src/in_memory.rs                                   |    301 |
| ./bft/monad-state-backend/src/lib.rs                                         |    137 |
| ./bft/monad-state-backend/src/mock.rs                                        |     66 |
| ./bft/monad-state-backend/src/thread.rs                                      |    281 |
| ./bft/monad-state/src/blocksync.rs                                           |    215 |
| ./bft/monad-state/src/consensus.rs                                           |    679 |
| ./bft/monad-state/src/epoch.rs                                               |    110 |
| ./bft/monad-state/src/lib.rs                                                 |   1424 |
| ./bft/monad-state/src/statesync.rs                                           |    178 |
| ./bft/monad-statesync/benches/ipc_bench.rs                                   |     69 |
| ./bft/monad-statesync/build.rs                                               |     21 |
| ./bft/monad-statesync/src/ffi.rs                                             |    452 |
| ./bft/monad-statesync/src/ipc.rs                                             |    606 |
| ./bft/monad-statesync/src/lib.rs                                             |    254 |
| ./bft/monad-statesync/src/outbound_requests.rs                               |    258 |
| ./bft/monad-system-calls/src/lib.rs                                          |    200 |
| ./bft/monad-system-calls/src/staking_contract.rs                             |    162 |
| ./bft/monad-system-calls/src/validator.rs                                    |    331 |
| ./bft/monad-tfm/src/arithmetic.rs                                            |    134 |
| ./bft/monad-tfm/src/base_fee.rs                                              |    301 |
| ./bft/monad-tfm/src/lib.rs                                                   |      2 |
| ./bft/monad-triedb-cache/src/lib.rs                                          |    167 |
| ./bft/monad-triedb-utils/examples/async.rs                                   |     28 |
| ./bft/monad-triedb-utils/examples/triedb-bench.rs                            |    309 |
| ./bft/monad-triedb-utils/src/decode.rs                                       |     97 |
| ./bft/monad-triedb-utils/src/key.rs                                          |    160 |
| ./bft/monad-triedb-utils/src/lib.rs                                          |    264 |
| ./bft/monad-triedb-utils/src/mock_triedb.rs                                  |    150 |
| ./bft/monad-triedb-utils/src/triedb_env.rs                                   |   1075 |
| ./bft/monad-triedb/build.rs                                                  |     29 |
| ./bft/monad-triedb/src/lib.rs                                                |    416 |
| ./bft/monad-types/src/lib.rs                                                 |    659 |
| ./bft/monad-updaters/src/config_file.rs                                      |    186 |
| ./bft/monad-updaters/src/config_loader.rs                                    |    210 |
| ./bft/monad-updaters/src/ledger.rs                                           |    225 |
| ./bft/monad-updaters/src/lib.rs                                              |    139 |
| ./bft/monad-updaters/src/local_router.rs                                     |    160 |
| ./bft/monad-updaters/src/loopback.rs                                         |     63 |
| ./bft/monad-updaters/src/parent.rs                                           |    219 |
| ./bft/monad-updaters/src/statesync.rs                                        |    220 |
| ./bft/monad-updaters/src/timer.rs                                            |    397 |
| ./bft/monad-updaters/src/timestamp.rs                                        |     58 |
| ./bft/monad-updaters/src/tokio_timestamp.rs                                  |     69 |
| ./bft/monad-updaters/src/triedb_val_set.rs                                   |    165 |
| ./bft/monad-updaters/src/txpool.rs                                           |    520 |
| ./bft/monad-updaters/src/val_set.rs                                          |    295 |
| ./bft/monad-validator/src/epoch_manager.rs                                   |     53 |
| ./bft/monad-validator/src/leader_election.rs                                 |     14 |
| ./bft/monad-validator/src/lib.rs                                             |      8 |
| ./bft/monad-validator/src/signature_collection.rs                            |     99 |
| ./bft/monad-validator/src/simple_round_robin.rs                              |     26 |
| ./bft/monad-validator/src/validator_mapping.rs                               |     20 |
| ./bft/monad-validator/src/validator_set.rs                                   |    289 |
| ./bft/monad-validator/src/validators_epoch_mapping.rs                        |     84 |
| ./bft/monad-validator/src/weighted_round_robin.rs                            |    220 |
| ./monad/category/async/concepts.hpp                                          |     46 |
| ./monad/category/async/config.hpp                                            |    177 |
| ./monad/category/async/connected_operation.hpp                               |    317 |
| ./monad/category/async/detail/connected_operation_storage.hpp                |    342 |
| ./monad/category/async/detail/scope_polyfill.hpp                             |    175 |
| ./monad/category/async/detail/start_lifetime_as_polyfill.hpp                 |     62 |
| ./monad/category/async/erased_connected_operation.hpp                        |    456 |
| ./monad/category/async/io_senders.hpp                                        |    304 |
| ./monad/category/async/io.cpp                                                |    669 |
| ./monad/category/async/io.hpp                                                |    562 |
| ./monad/category/async/sender_errc.hpp                                       |    291 |
| ./monad/category/async/storage_pool.cpp                                      |    805 |
| ./monad/category/async/storage_pool.hpp                                      |    276 |
| ./monad/category/async/util.cpp                                              |    111 |
| ./monad/category/async/util.hpp                                              |     38 |
| ./monad/category/core/array.hpp                                              |     23 |
| ./monad/category/core/assert.c                                               |     56 |
| ./monad/category/core/assert.h                                               |     98 |
| ./monad/category/core/backtrace.cpp                                          |    165 |
| ./monad/category/core/backtrace.hpp                                          |     35 |
| ./monad/category/core/basic_formatter.hpp                                    |     14 |
| ./monad/category/core/blake3.hpp                                             |     18 |
| ./monad/category/core/byte_string.hpp                                        |     25 |
| ./monad/category/core/bytes_hash_compare.hpp                                 |     20 |
| ./monad/category/core/bytes.hpp                                              |     49 |
| ./monad/category/core/cleanup.c                                              |     27 |
| ./monad/category/core/cleanup.h                                              |     12 |
| ./monad/category/core/cmemory.hpp                                            |     66 |
| ./monad/category/core/concat.h                                               |      3 |
| ./monad/category/core/config.hpp                                             |     19 |
| ./monad/category/core/cpu_relax.h                                            |      6 |
| ./monad/category/core/cpuset.c                                               |     31 |
| ./monad/category/core/cpuset.h                                               |     10 |
| ./monad/category/core/endian.hpp                                             |      3 |
| ./monad/category/core/event/event_iterator_inline.h                          |     77 |
| ./monad/category/core/event/event_iterator.h                                 |     34 |
| ./monad/category/core/event/event_metadata.h                                 |     15 |
| ./monad/category/core/event/event_recorder_inline.h                          |     78 |
| ./monad/category/core/event/event_recorder.h                                 |     29 |
| ./monad/category/core/event/event_ring_util.c                                |    262 |
| ./monad/category/core/event/event_ring_util.h                                |     31 |
| ./monad/category/core/event/event_ring.c                                     |    348 |
| ./monad/category/core/event/event_ring.h                                     |    168 |
| ./monad/category/core/fiber/config.hpp                                       |      8 |
| ./monad/category/core/fiber/priority_algorithm.cpp                           |     54 |
| ./monad/category/core/fiber/priority_algorithm.hpp                           |     34 |
| ./monad/category/core/fiber/priority_pool.cpp                                |     87 |
| ./monad/category/core/fiber/priority_pool.hpp                                |     33 |
| ./monad/category/core/fiber/priority_properties.hpp                          |     27 |
| ./monad/category/core/fiber/priority_queue.cpp                               |     18 |
| ./monad/category/core/fiber/priority_queue.hpp                               |     33 |
| ./monad/category/core/fiber/priority_task.hpp                                |     13 |
| ./monad/category/core/format_err.c                                           |     40 |
| ./monad/category/core/format_err.h                                           |     25 |
| ./monad/category/core/hash.hpp                                               |     30 |
| ./monad/category/core/hex_literal.hpp                                        |     55 |
| ./monad/category/core/int.hpp                                                |     24 |
| ./monad/category/core/io/buffer_pool.cpp                                     |     22 |
| ./monad/category/core/io/buffer_pool.hpp                                     |     26 |
| ./monad/category/core/io/buffers.cpp                                         |     86 |
| ./monad/category/core/io/buffers.hpp                                         |    112 |
| ./monad/category/core/io/config.hpp                                          |      8 |
| ./monad/category/core/io/ring.cpp                                            |     37 |
| ./monad/category/core/io/ring.hpp                                            |     63 |
| ./monad/category/core/keccak_impl.S                                          |      1 |
| ./monad/category/core/keccak.c                                               |     25 |
| ./monad/category/core/keccak.h                                               |     12 |
| ./monad/category/core/keccak.hpp                                             |     19 |
| ./monad/category/core/likely.h                                               |      3 |
| ./monad/category/core/log_ffi.cpp                                            |    211 |
| ./monad/category/core/log_ffi.h                                              |     28 |
| ./monad/category/core/lru/lru_cache.hpp                                      |    325 |
| ./monad/category/core/lru/static_lru_cache.hpp                               |     99 |
| ./monad/category/core/math_disas.cpp                                         |      9 |
| ./monad/category/core/math.hpp                                               |     14 |
| ./monad/category/core/mem/align.h                                            |     23 |
| ./monad/category/core/mem/allocators.hpp                                     |    273 |
| ./monad/category/core/mem/batch_mem_pool.hpp                                 |    109 |
| ./monad/category/core/mem/huge_mem.cpp                                       |     46 |
| ./monad/category/core/mem/huge_mem.hpp                                       |     43 |
| ./monad/category/core/mem/hugetlb_path.c                                     |    145 |
| ./monad/category/core/mem/hugetlb_path.h                                     |     20 |
| ./monad/category/core/monad_exception.cpp                                    |     53 |
| ./monad/category/core/monad_exception.hpp                                    |     43 |
| ./monad/category/core/nibble.h                                               |     27 |
| ./monad/category/core/procfs/statm.c                                         |     33 |
| ./monad/category/core/procfs/statm.h                                         |     11 |
| ./monad/category/core/result.hpp                                             |      9 |
| ./monad/category/core/rlp/config.hpp                                         |     15 |
| ./monad/category/core/rlp/encode_disas.cpp                                   |     37 |
| ./monad/category/core/rlp/encode.hpp                                         |    138 |
| ./monad/category/core/size_of.hpp                                            |      6 |
| ./monad/category/core/small_prng.hpp                                         |     65 |
| ./monad/category/core/spinlock_disas.c                                       |     17 |
| ./monad/category/core/spinlock.h                                             |     49 |
| ./monad/category/core/srcloc.h                                               |     11 |
| ./monad/category/core/synchronization/spin_lock.hpp                          |    123 |
| ./monad/category/core/third_party/ankerl/robin_hood.h                        |   1854 |
| ./monad/category/core/third_party/openssl/crypto/sha/asm/keccak1600-avx2.S   |    543 |
| ./monad/category/core/third_party/openssl/crypto/sha/asm/keccak1600-avx512.S |    405 |
| ./monad/category/core/third_party/openssl/crypto/sha/keccak1600.c            |    974 |
| ./monad/category/core/tl_tid.c                                               |      8 |
| ./monad/category/core/tl_tid.h                                               |     18 |
| ./monad/category/core/unaligned.hpp                                          |     12 |
| ./monad/category/core/unordered_map.hpp                                      |    108 |
| ./monad/category/core/util/stopwatch.hpp                                     |     30 |
| ./monad/category/event/example/eventwatch.c                                  |    272 |
| ./monad/category/execution/ethereum/block_hash_buffer.cpp                    |    162 |
| ./monad/category/execution/ethereum/block_hash_buffer.hpp                    |     66 |
| ./monad/category/execution/ethereum/block_hash_history.cpp                   |     51 |
| ./monad/category/execution/ethereum/block_hash_history.hpp                   |     14 |
| ./monad/category/execution/ethereum/block_reward.cpp                         |     70 |
| ./monad/category/execution/ethereum/block_reward.hpp                         |     10 |
| ./monad/category/execution/ethereum/chain/chain_config.h                     |     16 |
| ./monad/category/execution/ethereum/chain/chain.cpp                          |     12 |
| ./monad/category/execution/ethereum/chain/chain.hpp                          |     34 |
| ./monad/category/execution/ethereum/chain/ethereum_mainnet_alloc.hpp         |  26687 |
| ./monad/category/execution/ethereum/chain/ethereum_mainnet.cpp               |    144 |
| ./monad/category/execution/ethereum/chain/ethereum_mainnet.hpp               |     35 |
| ./monad/category/execution/ethereum/chain/genesis_state.cpp                  |     45 |
| ./monad/category/execution/ethereum/chain/genesis_state.hpp                  |     12 |
| ./monad/category/execution/ethereum/core/account.hpp                         |     30 |
| ./monad/category/execution/ethereum/core/address.hpp                         |     17 |
| ./monad/category/execution/ethereum/core/base_ctypes.h                       |     62 |
| ./monad/category/execution/ethereum/core/block.hpp                           |     50 |
| ./monad/category/execution/ethereum/core/contract/abi_decode_error.cpp       |     15 |
| ./monad/category/execution/ethereum/core/contract/abi_decode_error.hpp       |     29 |
| ./monad/category/execution/ethereum/core/contract/abi_decode.hpp             |     45 |
| ./monad/category/execution/ethereum/core/contract/abi_encode.hpp             |    117 |
| ./monad/category/execution/ethereum/core/contract/abi_signatures.hpp         |     21 |
| ./monad/category/execution/ethereum/core/contract/big_endian.hpp             |     57 |
| ./monad/category/execution/ethereum/core/contract/checked_math.cpp           |     57 |
| ./monad/category/execution/ethereum/core/contract/checked_math.hpp           |     37 |
| ./monad/category/execution/ethereum/core/contract/events.hpp                 |     32 |
| ./monad/category/execution/ethereum/core/contract/storage_array.hpp          |     57 |
| ./monad/category/execution/ethereum/core/contract/storage_variable.hpp       |     86 |
| ./monad/category/execution/ethereum/core/eth_ctypes.h                        |    103 |
| ./monad/category/execution/ethereum/core/fmt/account_fmt.hpp                 |     31 |
| ./monad/category/execution/ethereum/core/fmt/address_fmt.hpp                 |     22 |
| ./monad/category/execution/ethereum/core/fmt/block_fmt.hpp                   |     57 |
| ./monad/category/execution/ethereum/core/fmt/bytes_fmt.hpp                   |     22 |
| ./monad/category/execution/ethereum/core/fmt/int_fmt.hpp                     |     19 |
| ./monad/category/execution/ethereum/core/fmt/receipt_fmt.hpp                 |     56 |
| ./monad/category/execution/ethereum/core/fmt/signature_fmt.hpp               |     30 |
| ./monad/category/execution/ethereum/core/fmt/transaction_fmt.hpp             |     94 |
| ./monad/category/execution/ethereum/core/fmt/withdrawal_fmt.hpp              |     28 |
| ./monad/category/execution/ethereum/core/log_level_map.hpp                   |     20 |
| ./monad/category/execution/ethereum/core/receipt.cpp                         |     33 |
| ./monad/category/execution/ethereum/core/receipt.hpp                         |     31 |
| ./monad/category/execution/ethereum/core/rlp/account_rlp.cpp                 |     39 |
| ./monad/category/execution/ethereum/core/rlp/account_rlp.hpp                 |     10 |
| ./monad/category/execution/ethereum/core/rlp/address_rlp.hpp                 |     44 |
| ./monad/category/execution/ethereum/core/rlp/block_rlp.cpp                   |    190 |
| ./monad/category/execution/ethereum/core/rlp/block_rlp.hpp                   |     15 |
| ./monad/category/execution/ethereum/core/rlp/bytes_rlp.hpp                   |     27 |
| ./monad/category/execution/ethereum/core/rlp/int_rlp.hpp                     |     30 |
| ./monad/category/execution/ethereum/core/rlp/receipt_rlp.cpp                 |    153 |
| ./monad/category/execution/ethereum/core/rlp/receipt_rlp.hpp                 |     18 |
| ./monad/category/execution/ethereum/core/rlp/signature_rlp.cpp               |     17 |
| ./monad/category/execution/ethereum/core/rlp/signature_rlp.hpp               |      8 |
| ./monad/category/execution/ethereum/core/rlp/transaction_rlp.cpp             |    320 |
| ./monad/category/execution/ethereum/core/rlp/transaction_rlp.hpp             |     22 |
| ./monad/category/execution/ethereum/core/rlp/withdrawal_rlp.cpp              |     55 |
| ./monad/category/execution/ethereum/core/rlp/withdrawal_rlp.hpp              |     11 |
| ./monad/category/execution/ethereum/core/signature.cpp                       |     30 |
| ./monad/category/execution/ethereum/core/signature.hpp                       |     18 |
| ./monad/category/execution/ethereum/core/transaction.cpp                     |     57 |
| ./monad/category/execution/ethereum/core/transaction.hpp                     |     67 |
| ./monad/category/execution/ethereum/core/variant.hpp                         |     11 |
| ./monad/category/execution/ethereum/core/withdrawal.hpp                      |     15 |
| ./monad/category/execution/ethereum/create_contract_address.cpp              |     36 |
| ./monad/category/execution/ethereum/create_contract_address.hpp              |     11 |
| ./monad/category/execution/ethereum/dao.hpp                                  |    144 |
| ./monad/category/execution/ethereum/db/db_cache.hpp                          |    199 |
| ./monad/category/execution/ethereum/db/db_snapshot_filesystem.cpp            |    176 |
| ./monad/category/execution/ethereum/db/db_snapshot_filesystem.h              |     21 |
| ./monad/category/execution/ethereum/db/db_snapshot.cpp                       |    422 |
| ./monad/category/execution/ethereum/db/db_snapshot.h                         |     35 |
| ./monad/category/execution/ethereum/db/db.hpp                                |     70 |
| ./monad/category/execution/ethereum/db/file_db.cpp                           |     78 |
| ./monad/category/execution/ethereum/db/file_db.hpp                           |     22 |
| ./monad/category/execution/ethereum/db/trie_db.cpp                           |    641 |
| ./monad/category/execution/ethereum/db/trie_db.hpp                           |     89 |
| ./monad/category/execution/ethereum/db/trie_rodb.hpp                         |    151 |
| ./monad/category/execution/ethereum/db/util.cpp                              |    848 |
| ./monad/category/execution/ethereum/db/util.hpp                              |    128 |
| ./monad/category/execution/ethereum/dispatch_transaction.cpp                 |     30 |
| ./monad/category/execution/ethereum/dispatch_transaction.hpp                 |     34 |
| ./monad/category/execution/ethereum/event/exec_event_ctypes_metadata.c       |    132 |
| ./monad/category/execution/ethereum/event/exec_event_ctypes.h                |    177 |
| ./monad/category/execution/ethereum/event/exec_event_recorder.cpp            |    103 |
| ./monad/category/execution/ethereum/event/exec_event_recorder.hpp            |    182 |
| ./monad/category/execution/ethereum/event/exec_iter_help_inline.h            |    281 |
| ./monad/category/execution/ethereum/event/exec_iter_help.h                   |     38 |
| ./monad/category/execution/ethereum/event/record_block_events.cpp            |    107 |
| ./monad/category/execution/ethereum/event/record_block_events.hpp            |     24 |
| ./monad/category/execution/ethereum/event/record_txn_events.cpp              |    160 |
| ./monad/category/execution/ethereum/event/record_txn_events.hpp              |     15 |
| ./monad/category/execution/ethereum/evm.cpp                                  |    249 |
| ./monad/category/execution/ethereum/evm.hpp                                  |     22 |
| ./monad/category/execution/ethereum/evmc_host.cpp                            |    175 |
| ./monad/category/execution/ethereum/evmc_host.hpp                            |    155 |
| ./monad/category/execution/ethereum/execute_block.cpp                        |    268 |
| ./monad/category/execution/ethereum/execute_block.hpp                        |     33 |
| ./monad/category/execution/ethereum/execute_transaction.cpp                  |    365 |
| ./monad/category/execution/ethereum/execute_transaction.hpp                  |     81 |
| ./monad/category/execution/ethereum/fmt/event_trace_fmt.hpp                  |     13 |
| ./monad/category/execution/ethereum/metrics/block_metrics.hpp                |     27 |
| ./monad/category/execution/ethereum/precompiles_bls12.cpp                    |    352 |
| ./monad/category/execution/ethereum/precompiles_bls12.hpp                    |     90 |
| ./monad/category/execution/ethereum/precompiles_impl.cpp                     |    364 |
| ./monad/category/execution/ethereum/precompiles.cpp                          |    122 |
| ./monad/category/execution/ethereum/precompiles.hpp                          |     81 |
| ./monad/category/execution/ethereum/rlp/config.hpp                           |      8 |
| ./monad/category/execution/ethereum/rlp/decode_error.cpp                     |     29 |
| ./monad/category/execution/ethereum/rlp/decode_error.hpp                     |     34 |
| ./monad/category/execution/ethereum/rlp/decode.hpp                           |    121 |
| ./monad/category/execution/ethereum/rlp/encode2.hpp                          |     62 |
| ./monad/category/execution/ethereum/state2/block_state.cpp                   |    213 |
| ./monad/category/execution/ethereum/state2/block_state.hpp                   |     43 |
| ./monad/category/execution/ethereum/state2/fmt/state_deltas_fmt.hpp          |     81 |
| ./monad/category/execution/ethereum/state2/state_deltas.hpp                  |     40 |
| ./monad/category/execution/ethereum/state3/account_state.cpp                 |     50 |
| ./monad/category/execution/ethereum/state3/account_state.hpp                 |    106 |
| ./monad/category/execution/ethereum/state3/account_substate.hpp              |     61 |
| ./monad/category/execution/ethereum/state3/state.cpp                         |      1 |
| ./monad/category/execution/ethereum/state3/state.hpp                         |    550 |
| ./monad/category/execution/ethereum/state3/version_stack.hpp                 |     75 |
| ./monad/category/execution/ethereum/trace/call_frame.cpp                     |     56 |
| ./monad/category/execution/ethereum/trace/call_frame.hpp                     |     37 |
| ./monad/category/execution/ethereum/trace/call_tracer.cpp                    |    166 |
| ./monad/category/execution/ethereum/trace/call_tracer.hpp                    |     50 |
| ./monad/category/execution/ethereum/trace/event_trace.cpp                    |     54 |
| ./monad/category/execution/ethereum/trace/event_trace.hpp                    |     70 |
| ./monad/category/execution/ethereum/trace/prestate_tracer.cpp                |    225 |
| ./monad/category/execution/ethereum/trace/prestate_tracer.hpp                |     49 |
| ./monad/category/execution/ethereum/trace/rlp/call_frame_rlp.cpp             |     74 |
| ./monad/category/execution/ethereum/trace/rlp/call_frame_rlp.hpp             |     13 |
| ./monad/category/execution/ethereum/trace/tracer_config.h                    |     15 |
| ./monad/category/execution/ethereum/transaction_gas.cpp                      |    188 |
| ./monad/category/execution/ethereum/transaction_gas.hpp                      |     41 |
| ./monad/category/execution/ethereum/tx_context.cpp                           |     42 |
| ./monad/category/execution/ethereum/tx_context.hpp                           |     30 |
| ./monad/category/execution/ethereum/types/fmt/incarnation_fmt.hpp            |     27 |
| ./monad/category/execution/ethereum/types/incarnation.hpp                    |     39 |
| ./monad/category/execution/ethereum/validate_block.cpp                       |    215 |
| ./monad/category/execution/ethereum/validate_block.hpp                       |     58 |
| ./monad/category/execution/ethereum/validate_transaction.cpp                 |    217 |
| ./monad/category/execution/ethereum/validate_transaction.hpp                 |     63 |
| ./monad/category/execution/monad/chain/monad_chain.cpp                       |    229 |
| ./monad/category/execution/monad/chain/monad_chain.hpp                       |     56 |
| ./monad/category/execution/monad/chain/monad_devnet_alloc.hpp                |    278 |
| ./monad/category/execution/monad/chain/monad_devnet.cpp                      |     26 |
| ./monad/category/execution/monad/chain/monad_devnet.hpp                      |     15 |
| ./monad/category/execution/monad/chain/monad_mainnet_alloc.hpp               |     11 |
| ./monad/category/execution/monad/chain/monad_mainnet.cpp                     |     37 |
| ./monad/category/execution/monad/chain/monad_mainnet.hpp                     |     15 |
| ./monad/category/execution/monad/chain/monad_transaction_error.cpp           |     20 |
| ./monad/category/execution/monad/chain/monad_transaction_error.hpp           |     30 |
| ./monad/category/execution/monad/core/monad_block.hpp                        |    140 |
| ./monad/category/execution/monad/core/monad_ctypes.h                         |     15 |
| ./monad/category/execution/monad/core/rlp/monad_block_rlp.cpp                |    166 |
| ./monad/category/execution/monad/core/rlp/monad_block_rlp.hpp                |     12 |
| ./monad/category/execution/monad/dispatch_transaction.cpp                    |     46 |
| ./monad/category/execution/monad/dispatch_transaction.hpp                    |     14 |
| ./monad/category/execution/monad/event/record_consensus_events.cpp           |     63 |
| ./monad/category/execution/monad/event/record_consensus_events.hpp           |     12 |
| ./monad/category/execution/monad/execute_system_transaction.cpp              |    170 |
| ./monad/category/execution/monad/execute_system_transaction.hpp              |     32 |
| ./monad/category/execution/monad/min_base_fee.cpp                            |      5 |
| ./monad/category/execution/monad/min_base_fee.h                              |     11 |
| ./monad/category/execution/monad/monad_precompiles_impl.cpp                  |     66 |
| ./monad/category/execution/monad/monad_precompiles.cpp                       |     58 |
| ./monad/category/execution/monad/monad_precompiles.hpp                       |     14 |
| ./monad/category/execution/monad/monad_transaction_gas.cpp                   |     28 |
| ./monad/category/execution/monad/monad_transaction_gas.hpp                   |     11 |
| ./monad/category/execution/monad/reserve_balance.cpp                         |      5 |
| ./monad/category/execution/monad/reserve_balance.h                           |     11 |
| ./monad/category/execution/monad/staking/config.hpp                          |     15 |
| ./monad/category/execution/monad/staking/read_valset.cpp                     |     57 |
| ./monad/category/execution/monad/staking/read_valset.hpp                     |     22 |
| ./monad/category/execution/monad/staking/staking_contract.cpp                |   1524 |
| ./monad/category/execution/monad/staking/staking_contract.hpp                |    308 |
| ./monad/category/execution/monad/staking/util/bls.cpp                        |     16 |
| ./monad/category/execution/monad/staking/util/bls.hpp                        |     66 |
| ./monad/category/execution/monad/staking/util/consensus_view.cpp             |     11 |
| ./monad/category/execution/monad/staking/util/consensus_view.hpp             |     36 |
| ./monad/category/execution/monad/staking/util/constants.hpp                  |     35 |
| ./monad/category/execution/monad/staking/util/delegator.cpp                  |     11 |
| ./monad/category/execution/monad/staking/util/delegator.hpp                  |    130 |
| ./monad/category/execution/monad/staking/util/secp256k1.cpp                  |     24 |
| ./monad/category/execution/monad/staking/util/secp256k1.hpp                  |     71 |
| ./monad/category/execution/monad/staking/util/staking_error.cpp              |     54 |
| ./monad/category/execution/monad/staking/util/staking_error.hpp              |     53 |
| ./monad/category/execution/monad/staking/util/val_execution.cpp              |     12 |
| ./monad/category/execution/monad/staking/util/val_execution.hpp              |    107 |
| ./monad/category/execution/monad/state2/proposal_state.hpp                   |    205 |
| ./monad/category/execution/monad/system_sender.hpp                           |      8 |
| ./monad/category/execution/monad/validate_monad_block.cpp                    |     72 |
| ./monad/category/execution/monad/validate_monad_block.hpp                    |     38 |
| ./monad/category/execution/monad/validate_system_transaction.cpp             |     92 |
| ./monad/category/execution/monad/validate_system_transaction.hpp             |     46 |
| ./monad/category/mpt/bench/async_read_bench.cpp                              |    472 |
| ./monad/category/mpt/cli_tool_impl.cpp                                       |   1526 |
| ./monad/category/mpt/cli_tool_impl.hpp                                       |      6 |
| ./monad/category/mpt/cli_tool_main.cpp                                       |     14 |
| ./monad/category/mpt/compute.cpp                                             |    100 |
| ./monad/category/mpt/compute.hpp                                             |    313 |
| ./monad/category/mpt/config.hpp                                              |     13 |
| ./monad/category/mpt/copy_trie.cpp                                           |    280 |
| ./monad/category/mpt/db_error.hpp                                            |     37 |
| ./monad/category/mpt/db.cpp                                                  |   1441 |
| ./monad/category/mpt/db.hpp                                                  |    215 |
| ./monad/category/mpt/deserialize_node_from_receiver_result.hpp               |     71 |
| ./monad/category/mpt/detail/boost_fiber_workarounds.hpp                      |    290 |
| ./monad/category/mpt/detail/collected_stats.hpp                              |     44 |
| ./monad/category/mpt/detail/db_metadata.hpp                                  |    461 |
| ./monad/category/mpt/detail/kbhit.hpp                                        |     65 |
| ./monad/category/mpt/detail/unsigned_20.hpp                                  |     76 |
| ./monad/category/mpt/find_notify_fiber.cpp                                   |    385 |
| ./monad/category/mpt/find_request_sender.hpp                                 |    256 |
| ./monad/category/mpt/find.cpp                                                |     65 |
| ./monad/category/mpt/merkle/compact_encode.hpp                               |     31 |
| ./monad/category/mpt/merkle/node_reference.hpp                               |     21 |
| ./monad/category/mpt/nibbles_view_fmt.hpp                                    |     22 |
| ./monad/category/mpt/nibbles_view.hpp                                        |    300 |
| ./monad/category/mpt/node_cache.hpp                                          |     64 |
| ./monad/category/mpt/node_cursor.hpp                                         |     54 |
| ./monad/category/mpt/node_disas.cpp                                          |     36 |
| ./monad/category/mpt/node.cpp                                                |    498 |
| ./monad/category/mpt/node.hpp                                                |    369 |
| ./monad/category/mpt/ondisk_db_config.hpp                                    |     39 |
| ./monad/category/mpt/read_node_blocking.cpp                                  |     53 |
| ./monad/category/mpt/request.hpp                                             |     73 |
| ./monad/category/mpt/state_machine.hpp                                       |     22 |
| ./monad/category/mpt/traverse_util.hpp                                       |     78 |
| ./monad/category/mpt/traverse.hpp                                            |    332 |
| ./monad/category/mpt/trie.cpp                                                |   1662 |
| ./monad/category/mpt/trie.hpp                                                |    892 |
| ./monad/category/mpt/update_aux.cpp                                          |   1478 |
| ./monad/category/mpt/update.hpp                                              |     59 |
| ./monad/category/mpt/upward_tnode.hpp                                        |    225 |
| ./monad/category/mpt/util.hpp                                                |    242 |
| ./monad/category/rpc/eth_call.cpp                                            |    772 |
| ./monad/category/rpc/eth_call.h                                              |     61 |
| ./monad/category/statesync/statesync_client_context.cpp                      |    118 |
| ./monad/category/statesync/statesync_client_context.hpp                      |     47 |
| ./monad/category/statesync/statesync_client.cpp                              |    178 |
| ./monad/category/statesync/statesync_client.h                                |     33 |
| ./monad/category/statesync/statesync_messages.h                              |     45 |
| ./monad/category/statesync/statesync_protocol.cpp                            |    211 |
| ./monad/category/statesync/statesync_protocol.hpp                            |     23 |
| ./monad/category/statesync/statesync_server_context.cpp                      |    259 |
| ./monad/category/statesync/statesync_server_context.hpp                      |     96 |
| ./monad/category/statesync/statesync_server_network.hpp                      |    149 |
| ./monad/category/statesync/statesync_server.cpp                              |    339 |
| ./monad/category/statesync/statesync_server.h                                |     18 |
| ./monad/category/statesync/statesync_version.cpp                             |     10 |
| ./monad/category/statesync/statesync_version.h                               |     11 |
| ./monad/category/vm/code.hpp                                                 |     61 |
| ./monad/category/vm/compiler.cpp                                             |    125 |
| ./monad/category/vm/compiler.hpp                                             |    184 |
| ./monad/category/vm/compiler/ir/basic_blocks.cpp                             |     65 |
| ./monad/category/vm/compiler/ir/basic_blocks.hpp                             |    420 |
| ./monad/category/vm/compiler/ir/instruction.hpp                              |    405 |
| ./monad/category/vm/compiler/ir/x86.cpp                                      |    439 |
| ./monad/category/vm/compiler/ir/x86.hpp                                      |     28 |
| ./monad/category/vm/compiler/ir/x86/emitter.cpp                              |   6291 |
| ./monad/category/vm/compiler/ir/x86/emitter.hpp                              |    827 |
| ./monad/category/vm/compiler/ir/x86/types.hpp                                |    105 |
| ./monad/category/vm/compiler/ir/x86/virtual_stack.cpp                        |    763 |
| ./monad/category/vm/compiler/ir/x86/virtual_stack.hpp                        |    405 |
| ./monad/category/vm/compiler/types.hpp                                       |     11 |
| ./monad/category/vm/core/assert.cpp                                          |     16 |
| ./monad/category/vm/core/assert.h                                            |     48 |
| ./monad/category/vm/core/cases.hpp                                           |      9 |
| ./monad/category/vm/evm/delegation.cpp                                       |     56 |
| ./monad/category/vm/evm/delegation.hpp                                       |     11 |
| ./monad/category/vm/evm/explicit_traits.hpp                                  |    138 |
| ./monad/category/vm/evm/monad/revision.h                                     |     16 |
| ./monad/category/vm/evm/opcodes_xmacro.hpp                                   |    266 |
| ./monad/category/vm/evm/opcodes.hpp                                          |    713 |
| ./monad/category/vm/evm/switch_traits.hpp                                    |     53 |
| ./monad/category/vm/evm/traits.hpp                                           |    148 |
| ./monad/category/vm/host.hpp                                                 |     42 |
| ./monad/category/vm/interpreter/call_runtime.hpp                             |     66 |
| ./monad/category/vm/interpreter/debug.hpp                                    |     45 |
| ./monad/category/vm/interpreter/entry.S                                      |     17 |
| ./monad/category/vm/interpreter/execute.cpp                                  |     53 |
| ./monad/category/vm/interpreter/execute.hpp                                  |     13 |
| ./monad/category/vm/interpreter/instruction_stats.cpp                        |     65 |
| ./monad/category/vm/interpreter/instruction_stats.hpp                        |     12 |
| ./monad/category/vm/interpreter/instruction_table.hpp                        |   1550 |
| ./monad/category/vm/interpreter/instructions_fwd.hpp                         |    342 |
| ./monad/category/vm/interpreter/intercode.cpp                                |     47 |
| ./monad/category/vm/interpreter/intercode.hpp                                |     51 |
| ./monad/category/vm/interpreter/push.hpp                                     |    196 |
| ./monad/category/vm/interpreter/stack.hpp                                    |     66 |
| ./monad/category/vm/interpreter/types.hpp                                    |     30 |
| ./monad/category/vm/runtime/allocator.cpp                                    |      7 |
| ./monad/category/vm/runtime/allocator.hpp                                    |     21 |
| ./monad/category/vm/runtime/bin.hpp                                          |    107 |
| ./monad/category/vm/runtime/cached_allocator.hpp                             |    113 |
| ./monad/category/vm/runtime/call.hpp                                         |    225 |
| ./monad/category/vm/runtime/context.cpp                                      |    199 |
| ./monad/category/vm/runtime/context.S                                        |     67 |
| ./monad/category/vm/runtime/create.hpp                                       |    114 |
| ./monad/category/vm/runtime/data.hpp                                         |    171 |
| ./monad/category/vm/runtime/detail.hpp                                       |    125 |
| ./monad/category/vm/runtime/environment.hpp                                  |     43 |
| ./monad/category/vm/runtime/exit.cpp                                         |     22 |
| ./monad/category/vm/runtime/exit.S                                           |     15 |
| ./monad/category/vm/runtime/keccak.hpp                                       |     24 |
| ./monad/category/vm/runtime/log.hpp                                          |     90 |
| ./monad/category/vm/runtime/math.hpp                                         |     93 |
| ./monad/category/vm/runtime/math.S                                           |     85 |
| ./monad/category/vm/runtime/memory.hpp                                       |     41 |
| ./monad/category/vm/runtime/runtime.hpp                                      |     14 |
| ./monad/category/vm/runtime/selfdestruct.hpp                                 |     49 |
| ./monad/category/vm/runtime/storage_costs.hpp                                |    297 |
| ./monad/category/vm/runtime/storage.cpp                                      |     44 |
| ./monad/category/vm/runtime/storage.hpp                                      |     82 |
| ./monad/category/vm/runtime/transmute.hpp                                    |     96 |
| ./monad/category/vm/runtime/transmute.S                                      |     87 |
| ./monad/category/vm/runtime/types.hpp                                        |    280 |
| ./monad/category/vm/runtime/uint256.cpp                                      |     79 |
| ./monad/category/vm/runtime/uint256.hpp                                      |   1061 |
| ./monad/category/vm/utils/debug.cpp                                          |     11 |
| ./monad/category/vm/utils/debug.hpp                                          |     19 |
| ./monad/category/vm/utils/evm-as.hpp                                         |     74 |
| ./monad/category/vm/utils/evm-as/builder.hpp                                 |    624 |
| ./monad/category/vm/utils/evm-as/compiler.cpp                                |     63 |
| ./monad/category/vm/utils/evm-as/compiler.hpp                                |    321 |
| ./monad/category/vm/utils/evm-as/instruction.hpp                             |    191 |
| ./monad/category/vm/utils/evm-as/kernel-builder.hpp                          |    329 |
| ./monad/category/vm/utils/evm-as/resolver.hpp                                |     96 |
| ./monad/category/vm/utils/evm-as/utils.hpp                                   |     14 |
| ./monad/category/vm/utils/evm-as/validator.hpp                               |    171 |
| ./monad/category/vm/utils/evmc_utils.cpp                                     |     15 |
| ./monad/category/vm/utils/evmc_utils.hpp                                     |     46 |
| ./monad/category/vm/utils/load_program.hpp                                   |     37 |
| ./monad/category/vm/utils/log_utils.hpp                                      |     43 |
| ./monad/category/vm/utils/lru_weight_cache.hpp                               |    244 |
| ./monad/category/vm/utils/parser.cpp                                         |    291 |
| ./monad/category/vm/utils/parser.hpp                                         |     19 |
| ./monad/category/vm/utils/rc_ptr.hpp                                         |    139 |
| ./monad/category/vm/utils/scope_exit.hpp                                     |     49 |
| ./monad/category/vm/utils/traits.hpp                                         |     10 |
| ./monad/category/vm/varcode_cache.cpp                                        |     49 |
| ./monad/category/vm/varcode_cache.hpp                                        |     46 |
| ./monad/category/vm/vm.cpp                                                   |    174 |
| ./monad/category/vm/vm.hpp                                                   |    183 |
| Sum                                                                          | 164246 |


### Files out of scope

Any code not reachable via a running node under default configuration (e.g., test, mock or fuzzing code) is out of scope. Any project, development, build configuration or build, scripting or other miscellaneous development or testing files are out of scope. 

_Note re: default configuration: `MONAD_FOUR` is the relevant feature set for execution, despite the fact that the mainnet config in this commit references `MONAD_THREE`._

Findings concerning known vulnerabilities within third-party dependencies (‘**/third_party/*’) themselves are out of scope. However, a bug is considered a valid finding if it leads to a protocol-level vulnerability.

Any proof of concepts must demonstrate how the report is triggerable by an attacker, outlining the full attack path on a default node configuration, which exploits in-scope code.


# Additional context

## Areas of concern (where to focus for bugs)

The team's primary concerns for the Monad protocol are focused on the following components:

- **Consensus Safety:** The stability of the MonadBFT consensus mechanism is paramount.
    -	Malicious validator activity and its potential to disrupt the consensus process.
    -	General safety or liveness issues and disruption of the consensus process that can arise from a byzantine validator activity (within protocol assumptions of < 1/3 stake)
    -	The possibility of a faulty node causing a chain split or incorrect finality.
    -	Exploitation of the leader election process for unfair advantage.
-	**Networking Layer (RaptorCast):** The custom message delivery protocol is a potential attack surface.
    -	Abuse of the broadcast tree by a malicious node to delay block propagation.
    -	Denial-of-Service (DoS) attacks via spamming with invalid or malformed RaptorCast chunks.
    -	Vulnerabilities in the signature and Merkle tree verification logic.
    -	Incorrect encoding or decoding of messages, or tampering of messages
    -	Exploitation of the local mempool and transaction forwarding to create race conditions.
-	**Parallel Execution and State Integrity:** Parallel execution is a core innovation and a critical area of concern.
    -	Potential for non-deterministic outcomes or state mismatches between nodes.
    -	Accurate and robust read/write set analysis.
    -	Risk of non-deterministic outcomes from asynchronous execution.
-	**Transaction and Fee Model:** The custom gas model requires scrutiny.
    -	Manipulation of the gas limit for DoS attacks.
    -	Correctness and resistance to overflow/underflow in fee calculations.
    -	Correct handling of unexpected state reversions.
-	**MonadDB Integrity:** The custom database (`MonadDB`) is essential for state management.
    -	Corruption or bypassing of database integrity checks.
    -	Race conditions in parallel state access.
-	**JIT VM and Interpreter:** The Just-In-Time (JIT) compiler is a highly sensitive component.
    -	Differences in execution output between interpreted and JIT-compiled EVM bytecode.
    -	Potential for a malicious contract to achieve **remote code execution (RCE)**.
    -	Data persistence or corruption in the cache after a transaction rollback.

## Main invariants

-	**Consensus:** The network must achieve consensus on a single, canonical block order if a supermajority of stake weight is non-faulty. All honest nodes must arrive at the exact same committed final state.
-	**Chain finality:** Speculative execution results of a previous block will be finalized within the designated system parameters if a supermajority of nodes are participating in consensus
-	**Execution:** The outcome of any transaction, including failure, is deterministic regardless of the execution path (interpreter or JIT). The final state of a block must be identical across all nodes.
-	**State Integrity:** The blockchain state must be consistent and verifiable at all block heights. The `merkle root` from a delayed block D must be agreed upon by all nodes to prevent state divergence. The total native token supply shall not exceed the maximum configured supply.
-	**Transactions:** The total token deduction from a sender's balance must be equal to the sum of `value` and the product of `gas_price` and `gas_limit`. A transaction's `max_expenditure` shall not exceed the sender's available balance at the time of consensus.
-	**Networking:** All RaptorCast chunks must have a valid signature from the originator. The network must guarantee reliable message delivery to all non-faulty nodes if a supermajority of stake weight is non-faulty.
-	**EVM Compatibility:** Aside from the known deviations mentioned, execution of a transaction should conform to existing EVM specifications.

## All trusted roles in the protocol

- **StateSync Peer**	
  -	**Purpose:** Trusted nodes that provide state synchronization data during initial sync or catch-up 
  -	**Who can be a StateSync Peer:** Nodes explicitly configured in the `state_sync_peers` list, which defaults to bootstrap nodes if none specified

## Running tests

More detailed information about requirements and recommended build procedures are found in the individual
`README.md` files for the respective directories:
- [`monad`](./monad/README.md#building-the-source-code)
- [`bft`](./bft/README.md#getting-started)

```bash
git clone https://github.com/code-423n4/2025-09-monad.git --recursive
cd 2025-09-monad.git


# for monad-bft:
cd bft/monad-<insert crate name>
cargo test

# To run all tests at once, from the main folder
cd bft
cargo test --workspace


# for monad, run the following from the main folder
# Whole project tests
./monad/scripts/configure.sh
./monad/scripts/build.sh
./monad/scripts/test.sh

# VM Specific tests (after running the project tests above)
./monad/build/test/vm/unit/vm-unit-tests
```
Note: Individual crate tests can be run from each crate as standard

To run a consensus client + execution client + JsonRPC:
1.	cd docker/single-node
2.	nets/run.sh



**Additional Comments**

The codebase uses features of the Linux kernel and makes use of instructions specific to x86 such as AVX. It further requires Rust 1.87 and Clang 19 or newer.

For more information on build environment configuration, you can refer to [the docker build configurations](https://github.com/category-labs/monad/blob/8cd73a6186366fe52529ab1050b2e6a388af4893/docker/release.Dockerfile#L1-L87)


## Miscellaneous
Employees of Category Labs or Asymmetric Research, and employees' family members are ineligible to participate in this audit.

Code4rena's rules cannot be overridden by the contents of this README. In case of doubt, please check with C4 staff.
