;; ZenithFrame - Supply Chain Recall Orchestration Platform

;; This contract implements:
;;   - Product batch registration and tracking
;;   - Recall Readiness Scoring
;;   - Dynamic Quarantine Protocols
;;   - Supplier penalty enforcement via time-locked escrow
;;   - Audit trail for regulatory compliance

;; ============================================================
;; CONSTANTS
;; ============================================================

(define-constant CONTRACT-OWNER tx-sender)

(define-constant ERR-NOT-AUTHORIZED         (err u100))
(define-constant ERR-BATCH-NOT-FOUND        (err u101))
(define-constant ERR-BATCH-ALREADY-EXISTS   (err u102))
(define-constant ERR-ALREADY-QUARANTINED    (err u103))
(define-constant ERR-NOT-QUARANTINED        (err u104))
(define-constant ERR-SUPPLIER-NOT-FOUND     (err u105))
(define-constant ERR-ESCROW-NOT-FOUND       (err u106))
(define-constant ERR-ESCROW-NOT-MATURED     (err u107))
(define-constant ERR-ESCROW-ALREADY-CLAIMED (err u108))
(define-constant ERR-INVALID-SCORE          (err u109))
(define-constant ERR-RECALL-NOT-FOUND       (err u110))
(define-constant ERR-INVALID-PARAM          (err u111))

;; Batch status codes
(define-constant STATUS-ACTIVE      u0)
(define-constant STATUS-QUARANTINED u1)
(define-constant STATUS-RECALLED    u2)
(define-constant STATUS-CLEARED     u3)

;; Recall severity levels
(define-constant SEVERITY-LOW      u1)
(define-constant SEVERITY-MEDIUM   u2)
(define-constant SEVERITY-HIGH     u3)
(define-constant SEVERITY-CRITICAL u4)

;; Escrow lock period in blocks (approx 30 days at ~10 min/block)
(define-constant ESCROW-LOCK-BLOCKS u4320)

;; Max recall readiness score (0-100)
(define-constant MAX-SCORE u100)

;; ============================================================
;; DATA VARS
;; ============================================================

(define-data-var recall-nonce       uint u0)
(define-data-var escrow-nonce       uint u0)
(define-data-var total-batches      uint u0)
(define-data-var total-recalls      uint u0)

;; ============================================================
;; DATA MAPS
;; ============================================================

;; Authorized regulators / platform admins
(define-map authorized-operators
  { operator: principal }
  { active: bool, role: (string-ascii 32) }
)

;; Supplier registry
(define-map suppliers
  { supplier-id: (string-ascii 64) }
  {
    owner:           principal,
    name:            (string-ascii 128),
    readiness-score: uint,      ;; 0-100 Recall Readiness Score
    total-batches:   uint,
    active-recalls:  uint,
    penalty-balance: uint,      ;; accumulated STX penalties (micro-STX)
    registered-at:   uint       ;; block height
  }
)

;; Product batch registry
(define-map product-batches
  { batch-id: (string-ascii 64) }
  {
    supplier-id:     (string-ascii 64),
    product-code:    (string-ascii 64),
    description:     (string-ascii 256),
    quantity:        uint,
    manufacture-date: uint,     ;; block height proxy
    expiry-date:     uint,      ;; block height proxy
    status:          uint,      ;; STATUS-* constants
    risk-score:      uint,      ;; 0-100 predictive risk score
    quarantine-at:   (optional uint),
    cleared-at:      (optional uint),
    registered-at:   uint
  }
)

;; Recall events
(define-map recall-events
  { recall-id: uint }
  {
    batch-id:        (string-ascii 64),
    supplier-id:     (string-ascii 64),
    severity:        uint,      ;; SEVERITY-* constants
    reason:          (string-ascii 256),
    initiated-by:    principal,
    initiated-at:    uint,      ;; block height
    resolved-at:     (optional uint),
    affected-units:  uint,
    regulatory-ref:  (string-ascii 64),   ;; e.g. "FDA-2024-001"
    is-resolved:     bool
  }
)

;; Audit trail - append-only log entries keyed by (batch-id, sequence)
(define-map audit-log
  { batch-id: (string-ascii 64), seq: uint }
  {
    action:     (string-ascii 64),
    actor:      principal,
    detail:     (string-ascii 256),
    block:      uint
  }
)

;; Per-batch audit sequence counter
(define-map audit-seq
  { batch-id: (string-ascii 64) }
  { seq: uint }
)

;; Time-locked escrow for automated supplier penalties
(define-map escrow-entries
  { escrow-id: uint }
  {
    supplier-id:   (string-ascii 64),
    recall-id:     uint,
    amount:        uint,        ;; micro-STX
    beneficiary:   principal,   ;; regulator or harmed party
    locked-until:  uint,        ;; block height
    is-claimed:    bool,
    created-at:    uint
  }
)

;; Federated quality intelligence shares (anonymized)
(define-map quality-signals
  { signal-id: (string-ascii 64) }
  {
    product-category: (string-ascii 64),
    risk-indicator:   uint,     ;; 0-100
    sample-size:      uint,
    contributed-at:   uint,
    contributor:      principal  ;; hashed/anonymized in practice
  }
)

;; ============================================================
;; PRIVATE HELPERS
;; ============================================================

(define-private (is-owner)
  (is-eq tx-sender CONTRACT-OWNER)
)

(define-private (is-operator)
  (match (map-get? authorized-operators { operator: tx-sender })
    entry (get active entry)
    false
  )
)

(define-private (is-authorized)
  (or (is-owner) (is-operator))
)

(define-private (get-audit-seq (batch-id (string-ascii 64)))
  (default-to u0
    (get seq (map-get? audit-seq { batch-id: batch-id }))
  )
)

(define-private (write-audit
  (batch-id (string-ascii 64))
  (action   (string-ascii 64))
  (detail   (string-ascii 256))
)
  (let ((seq (get-audit-seq batch-id)))
    (map-set audit-log
      { batch-id: batch-id, seq: seq }
      {
        action: action,
        actor:  tx-sender,
        detail: detail,
        block:  block-height
      }
    )
    (map-set audit-seq { batch-id: batch-id } { seq: (+ seq u1) })
  )
)

(define-private (clamp-score (score uint))
  (if (> score MAX-SCORE) MAX-SCORE score)
)

;; ============================================================
;; OPERATOR MANAGEMENT
;; ============================================================

;; Add or update an authorized operator
(define-public (set-operator (operator principal) (role (string-ascii 32)) (active bool))
  (begin
    (asserts! (is-owner) ERR-NOT-AUTHORIZED)
    (map-set authorized-operators { operator: operator } { active: active, role: role })
    (ok true)
  )
)

;; ============================================================
;; SUPPLIER FUNCTIONS
;; ============================================================

;; Register a new supplier
(define-public (register-supplier
  (supplier-id (string-ascii 64))
  (name        (string-ascii 128))
)
  (begin
    (asserts! (is-none (map-get? suppliers { supplier-id: supplier-id })) ERR-BATCH-ALREADY-EXISTS)
    (map-set suppliers
      { supplier-id: supplier-id }
      {
        owner:           tx-sender,
        name:            name,
        readiness-score: u50,   ;; default neutral score
        total-batches:   u0,
        active-recalls:  u0,
        penalty-balance: u0,
        registered-at:   block-height
      }
    )
    (ok true)
  )
)

;; Update a supplier's Recall Readiness Score (operator only)
(define-public (update-readiness-score
  (supplier-id (string-ascii 64))
  (score       uint)
)
  (begin
    (asserts! (is-authorized) ERR-NOT-AUTHORIZED)
    (asserts! (<= score MAX-SCORE) ERR-INVALID-SCORE)
    (match (map-get? suppliers { supplier-id: supplier-id })
      entry (begin
        (map-set suppliers
          { supplier-id: supplier-id }
          (merge entry { readiness-score: score })
        )
        (ok true)
      )
      ERR-SUPPLIER-NOT-FOUND
    )
  )
)

;; Read supplier info
(define-read-only (get-supplier (supplier-id (string-ascii 64)))
  (map-get? suppliers { supplier-id: supplier-id })
)

;; ============================================================
;; BATCH REGISTRATION
;; ============================================================

(define-public (register-batch
  (batch-id      (string-ascii 64))
  (supplier-id   (string-ascii 64))
  (product-code  (string-ascii 64))
  (description   (string-ascii 256))
  (quantity      uint)
  (expiry-blocks uint)   ;; number of blocks until expiry
  (risk-score    uint)
)
  (begin
    (asserts! (is-none (map-get? product-batches { batch-id: batch-id })) ERR-BATCH-ALREADY-EXISTS)
    (asserts! (is-some (map-get? suppliers { supplier-id: supplier-id })) ERR-SUPPLIER-NOT-FOUND)
    (asserts! (> quantity u0) ERR-INVALID-PARAM)
    (map-set product-batches
      { batch-id: batch-id }
      {
        supplier-id:      supplier-id,
        product-code:     product-code,
        description:      description,
        quantity:         quantity,
        manufacture-date: block-height,
        expiry-date:      (+ block-height expiry-blocks),
        status:           STATUS-ACTIVE,
        risk-score:       (clamp-score risk-score),
        quarantine-at:    none,
        cleared-at:       none,
        registered-at:    block-height
      }
    )
    ;; Increment supplier batch count
    (match (map-get? suppliers { supplier-id: supplier-id })
      s (map-set suppliers { supplier-id: supplier-id }
          (merge s { total-batches: (+ (get total-batches s) u1) }))
      false
    )
    (var-set total-batches (+ (var-get total-batches) u1))
    (write-audit batch-id "REGISTER" description)
    (ok true)
  )
)

;; Update predictive risk score on a batch (authorized only)
(define-public (update-batch-risk-score
  (batch-id   (string-ascii 64))
  (risk-score uint)
)
  (begin
    (asserts! (is-authorized) ERR-NOT-AUTHORIZED)
    (match (map-get? product-batches { batch-id: batch-id })
      batch (begin
        (map-set product-batches { batch-id: batch-id }
          (merge batch { risk-score: (clamp-score risk-score) })
        )
        (write-audit batch-id "RISK-UPDATE" "Predictive risk score updated")
        (ok true)
      )
      ERR-BATCH-NOT-FOUND
    )
  )
)

;; Read batch info
(define-read-only (get-batch (batch-id (string-ascii 64)))
  (map-get? product-batches { batch-id: batch-id })
)

;; ============================================================
;; DYNAMIC QUARANTINE PROTOCOL
;; ============================================================

;; Quarantine a product batch - freezes distribution
(define-public (quarantine-batch
  (batch-id (string-ascii 64))
  (reason   (string-ascii 256))
)
  (begin
    (asserts! (is-authorized) ERR-NOT-AUTHORIZED)
    (match (map-get? product-batches { batch-id: batch-id })
      batch (begin
        (asserts! (is-eq (get status batch) STATUS-ACTIVE) ERR-ALREADY-QUARANTINED)
        (map-set product-batches { batch-id: batch-id }
          (merge batch {
            status:        STATUS-QUARANTINED,
            quarantine-at: (some block-height)
          })
        )
        (write-audit batch-id "QUARANTINE" reason)
        (ok true)
      )
      ERR-BATCH-NOT-FOUND
    )
  )
)

;; Lift quarantine and clear batch
(define-public (clear-batch
  (batch-id (string-ascii 64))
  (reason   (string-ascii 256))
)
  (begin
    (asserts! (is-authorized) ERR-NOT-AUTHORIZED)
    (match (map-get? product-batches { batch-id: batch-id })
      batch (begin
        (asserts! (is-eq (get status batch) STATUS-QUARANTINED) ERR-NOT-QUARANTINED)
        (map-set product-batches { batch-id: batch-id }
          (merge batch {
            status:     STATUS-CLEARED,
            cleared-at: (some block-height)
          })
        )
        (write-audit batch-id "CLEARED" reason)
        (ok true)
      )
      ERR-BATCH-NOT-FOUND
    )
  )
)

;; ============================================================
;; RECALL MANAGEMENT
;; ============================================================

;; Initiate a formal product recall
(define-public (initiate-recall
  (batch-id       (string-ascii 64))
  (severity       uint)
  (reason         (string-ascii 256))
  (affected-units uint)
  (regulatory-ref (string-ascii 64))
)
  (begin
    (asserts! (is-authorized) ERR-NOT-AUTHORIZED)
    (asserts! (and (>= severity SEVERITY-LOW) (<= severity SEVERITY-CRITICAL)) ERR-INVALID-PARAM)
    (match (map-get? product-batches { batch-id: batch-id })
      batch (begin
        (let (
          (recall-id   (var-get recall-nonce))
          (supplier-id (get supplier-id batch))
        )
          ;; Mark batch as recalled
          (map-set product-batches { batch-id: batch-id }
            (merge batch { status: STATUS-RECALLED })
          )
          ;; Create recall event
          (map-set recall-events
            { recall-id: recall-id }
            {
              batch-id:       batch-id,
              supplier-id:    supplier-id,
              severity:       severity,
              reason:         reason,
              initiated-by:   tx-sender,
              initiated-at:   block-height,
              resolved-at:    none,
              affected-units: affected-units,
              regulatory-ref: regulatory-ref,
              is-resolved:    false
            }
          )
          ;; Update supplier active-recall count
          (match (map-get? suppliers { supplier-id: supplier-id })
            s (map-set suppliers { supplier-id: supplier-id }
                (merge s { active-recalls: (+ (get active-recalls s) u1) })
              )
            false
          )
          (var-set recall-nonce (+ recall-id u1))
          (var-set total-recalls (+ (var-get total-recalls) u1))
          (write-audit batch-id "RECALL" reason)
          (ok recall-id)
        )
      )
      ERR-BATCH-NOT-FOUND
    )
  )
)

;; Resolve an open recall
(define-public (resolve-recall (recall-id uint))
  (begin
    (asserts! (is-authorized) ERR-NOT-AUTHORIZED)
    (match (map-get? recall-events { recall-id: recall-id })
      recall (begin
        (asserts! (not (get is-resolved recall)) ERR-BATCH-NOT-FOUND)
        (map-set recall-events { recall-id: recall-id }
          (merge recall {
            is-resolved: true,
            resolved-at: (some block-height)
          })
        )
        ;; Decrement supplier active recall count
        (match (map-get? suppliers { supplier-id: (get supplier-id recall) })
          s (map-set suppliers { supplier-id: (get supplier-id recall) }
              (merge s {
                active-recalls: (if (> (get active-recalls s) u0)
                  (- (get active-recalls s) u1)
                  u0
                )
              })
            )
          false
        )
        (write-audit (get batch-id recall) "RECALL-RESOLVED" "Recall resolved")
        (ok true)
      )
      ERR-RECALL-NOT-FOUND
    )
  )
)

;; Read recall event
(define-read-only (get-recall (recall-id uint))
  (map-get? recall-events { recall-id: recall-id })
)

;; ============================================================
;; TIME-LOCKED ESCROW - AUTOMATED PENALTY ENFORCEMENT
;; ============================================================

;; Operator locks STX as a penalty escrow tied to a recall
(define-public (create-penalty-escrow
  (supplier-id  (string-ascii 64))
  (recall-id    uint)
  (beneficiary  principal)
  (amount       uint)
)
  (begin
    (asserts! (is-authorized) ERR-NOT-AUTHORIZED)
    (asserts! (is-some (map-get? suppliers { supplier-id: supplier-id })) ERR-SUPPLIER-NOT-FOUND)
    (asserts! (is-some (map-get? recall-events { recall-id: recall-id })) ERR-RECALL-NOT-FOUND)
    (asserts! (> amount u0) ERR-INVALID-PARAM)
    ;; Transfer STX from caller into contract
    (try! (stx-transfer? amount tx-sender (as-contract tx-sender)))
    (let ((escrow-id (var-get escrow-nonce)))
      (map-set escrow-entries
        { escrow-id: escrow-id }
        {
          supplier-id:  supplier-id,
          recall-id:    recall-id,
          amount:       amount,
          beneficiary:  beneficiary,
          locked-until: (+ block-height ESCROW-LOCK-BLOCKS),
          is-claimed:   false,
          created-at:   block-height
        }
      )
      ;; Track penalty on supplier record
      (match (map-get? suppliers { supplier-id: supplier-id })
        s (map-set suppliers { supplier-id: supplier-id }
            (merge s { penalty-balance: (+ (get penalty-balance s) amount) })
          )
        false
      )
      (var-set escrow-nonce (+ escrow-id u1))
      (ok escrow-id)
    )
  )
)

;; Beneficiary claims escrow after lock period expires
(define-public (claim-escrow (escrow-id uint))
  (match (map-get? escrow-entries { escrow-id: escrow-id })
    escrow (begin
      (asserts! (is-eq tx-sender (get beneficiary escrow)) ERR-NOT-AUTHORIZED)
      (asserts! (not (get is-claimed escrow)) ERR-ESCROW-ALREADY-CLAIMED)
      (asserts! (>= block-height (get locked-until escrow)) ERR-ESCROW-NOT-MATURED)
      (map-set escrow-entries { escrow-id: escrow-id }
        (merge escrow { is-claimed: true })
      )
      (as-contract (stx-transfer? (get amount escrow) tx-sender (get beneficiary escrow)))
    )
    ERR-ESCROW-NOT-FOUND
  )
)

;; Read escrow info
(define-read-only (get-escrow (escrow-id uint))
  (map-get? escrow-entries { escrow-id: escrow-id })
)

;; ============================================================
;; FEDERATED QUALITY INTELLIGENCE (anonymized signal sharing)
;; ============================================================

;; Contribute an anonymized quality signal to the federated network
(define-public (contribute-quality-signal
  (signal-id        (string-ascii 64))
  (product-category (string-ascii 64))
  (risk-indicator   uint)
  (sample-size      uint)
)
  (begin
    (asserts! (is-none (map-get? quality-signals { signal-id: signal-id })) ERR-BATCH-ALREADY-EXISTS)
    (asserts! (<= risk-indicator MAX-SCORE) ERR-INVALID-SCORE)
    (asserts! (> sample-size u0) ERR-INVALID-PARAM)
    (map-set quality-signals
      { signal-id: signal-id }
      {
        product-category: product-category,
        risk-indicator:   risk-indicator,
        sample-size:      sample-size,
        contributed-at:   block-height,
        contributor:      tx-sender
      }
    )
    (ok true)
  )
)

;; Read a quality signal
(define-read-only (get-quality-signal (signal-id (string-ascii 64)))
  (map-get? quality-signals { signal-id: signal-id })
)

;; ============================================================
;; AUDIT TRAIL READ FUNCTIONS
;; ============================================================

;; Read a specific audit log entry
(define-read-only (get-audit-entry
  (batch-id (string-ascii 64))
  (seq      uint)
)
  (map-get? audit-log { batch-id: batch-id, seq: seq })
)

;; Get total audit entries for a batch
(define-read-only (get-audit-count (batch-id (string-ascii 64)))
  (get-audit-seq batch-id)
)

;; ============================================================
;; PLATFORM STATISTICS
;; ============================================================

(define-read-only (get-platform-stats)
  {
    total-batches:  (var-get total-batches),
    total-recalls:  (var-get total-recalls),
    contract-owner: CONTRACT-OWNER
  }
)
