export { hashLeaf, hashNode, type Hash } from './hash.js'
export { orderedMapRoot, orderedMapProof, verifyOrderedMapProof, type MapEntry, type MapProof, type MapPathStep } from './ordered-map.js'
export { merkleRoot, inclusionProof, verifyInclusion, consistencyProof, verifyConsistency } from './history.js'
export { registryEntryBytes, registryCheckpointHash, signRegistryCheckpoint,
  verifyRegistryCheckpoint, verifyRegistryExtension,
  type RegistryEntry, type RegistryCheckpoint, type SignedRegistryCheckpoint } from './registry.js'
export { createRegistryReplaySession, type RegistryReplaySession,
  type RegistryReplaySnapshot } from './registry-replay.js'
export { emptyHistoryFrontier, appendHistory, historyFrontierRoot, type HistoryFrontier } from './history-frontier.js'
export { canonicalJson, canonicalBytes, parseCanonical, type JsonValue } from './canonical.js'
export { encodeBase64Url, decodeBase64Url } from './encoding.js'
export { generateSigningKey, exportSigningPublicKey, importSigningPublicKey, exportSigningPrivateKey, importSigningPrivateKey, signingKeyId, signRecord, verifyRecord } from './signatures.js'
export { createEvidenceSalt, exportEvidenceSalt, commitEvidence, verifyEvidenceOpening, type EvidenceSalt } from './evidence-commitment.js'
export { checkpointHash, signCheckpoint, verifyCheckpoint, verifyCheckpointExtension, type GovernanceCheckpoint, type SignedCheckpoint } from './checkpoint.js'
export { importProofAccessPublicKey, blindProofAccess, finalizeProofAccess, verifyProofAccess, proofAccessNullifier, type ProofAccessBlindState, type ProofAccessToken } from './blind-proof-access.js'
export { createAuthorityAnchor, signAuthorityAnchor, anchorHash, verifyAuthorityAnchor, authorityStateSnapshot, authorityMapKey, authorityBindingHash, observerPolicyHash, authorityRevisionHash, signAuthorityRevision, signAuthorityBindingOperation, signAuthorityBindingRevision, recoveryResetCore, applyAuthorityRevision, replayAuthorityRevisions, authorityRevisionLeaf, type AuthorityAnchor, type SignedAuthorityAnchor, type AuthorityScope, type ActiveBinding, type RevokedBinding, type AuthorityBinding, type AuthorityOperation, type AuthorityRevision, type SignedAuthorityRevision, type RecoveryResetCore, type AuthoritySnapshot, type AuthorityState } from './authority-lifecycle.js'
export { signGovernanceAction, verifyGovernanceAction, governanceActionHash, governanceCompletionLeaf, type GovernanceAction, type SignedAction } from './action.js'
export { completionReceiptHash, verifyReceiptInclusion, type CompletionReceipt } from './completion-receipt.js'
export { recipientKeyClaimHash, type RecipientKeyClaim } from './recipient-key.js'
export { replayGovernanceHistory, createGovernanceReplaySession, type GovernanceReplaySnapshot, type GovernanceReplaySession } from './replay.js'
export { signObserverReport, verifyObserverReport, observerEvidenceSetDigest, observerFindingHash,
  type ObserverReportScope, type ObserverReportStatement, type SignedObserverReport } from './observer-report.js'
export { signAggregateReport, verifyAggregateReport, aggregateFeedStatusProof,
  verifyAggregateFeedStatus, type AggregateReportStatement, type SignedAggregateReport,
  type AggregateFeedStatus, type AggregateFeedStatusProof } from './observer-aggregate.js'
export { authorityId, authoritySubjectId, type AuthorityIdKind, type AuthoritySubjectIdentity } from './authority-ids.js'
