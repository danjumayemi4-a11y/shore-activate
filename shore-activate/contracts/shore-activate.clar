;; TrustChain - Supply Chain Transparency Smart Contract
;; Implements product registration, fingerprinting, transfer tracking,
;; compliance verification, and zero-knowledge proof anchoring.

;; ============================================================
;; CONSTANTS
;; ============================================================

(define-constant CONTRACT-OWNER tx-sender)

(define-constant ERR-NOT-AUTHORIZED        (err u100))
(define-constant ERR-PRODUCT-NOT-FOUND     (err u101))
(define-constant ERR-PRODUCT-EXISTS        (err u102))
(define-constant ERR-INVALID-STATUS        (err u103))
(define-constant ERR-NOT-CUSTODIAN         (err u104))
(define-constant ERR-COMPLIANCE-FAILED     (err u105))
(define-constant ERR-PARTNER-NOT-FOUND     (err u106))
(define-constant ERR-PARTNER-EXISTS        (err u107))

;; Product status codes
(define-constant STATUS-ACTIVE      u1)
(define-constant STATUS-FLAGGED     u2)
(define-constant STATUS-RECALLED    u3)
(define-constant STATUS-RETIRED     u4)

;; ============================================================
;; DATA MAPS & VARS
;; ============================================================

;; Registry of authorized supply-chain partners
(define-map partners
  { partner: principal }
  {
    name:       (string-ascii 64),
    role:       (string-ascii 32),   ;; e.g. "manufacturer", "distributor", "retailer"
    active:     bool,
    registered-at: uint
  }
)

;; Core product record
(define-map products
  { product-id: (buff 32) }
  {
    name:           (string-ascii 128),
    category:       (string-ascii 64),  ;; e.g. "pharmaceutical", "luxury", "food"
    manufacturer:   principal,
    fingerprint:    (buff 64),          ;; cryptographic product DNA hash
    status:         uint,
    custodian:      principal,          ;; current holder in supply chain
    created-at:     uint,
    updated-at:     uint
  }
)

;; Immutable custody / transfer log
(define-map custody-log
  { product-id: (buff 32), seq: uint }
  {
    from:        principal,
    to:          principal,
    location:    (string-ascii 128),
    transferred-at: uint,
    notes:       (string-ascii 256)
  }
)

;; Per-product transfer sequence counter
(define-map transfer-count
  { product-id: (buff 32) }
  { count: uint }
)

;; Compliance proof anchors (zero-knowledge proof hashes)
(define-map compliance-proofs
  { product-id: (buff 32), proof-id: uint }
  {
    proof-hash:   (buff 64),   ;; hash of the ZK proof
    standard:     (string-ascii 64), ;; e.g. "ISO-9001", "FDA-21CFR"
    verified-by:  principal,
    verified-at:  uint,
    passed:       bool
  }
)

;; Per-product proof counter
(define-map proof-count
  { product-id: (buff 32) }
  { count: uint }
)

;; Global counters
(define-data-var total-products uint u0)
(define-data-var total-partners  uint u0)

;; ============================================================
;; PRIVATE HELPERS
;; ============================================================

(define-private (is-contract-owner)
  (is-eq tx-sender CONTRACT-OWNER)
)

(define-private (is-active-partner (addr principal))
  (match (map-get? partners { partner: addr })
    entry (get active entry)
    false
  )
)

(define-private (product-exists (product-id (buff 32)))
  (is-some (map-get? products { product-id: product-id }))
)

(define-private (get-transfer-seq (product-id (buff 32)))
  (default-to u0
    (get count (map-get? transfer-count { product-id: product-id })))
)

(define-private (get-proof-seq (product-id (buff 32)))
  (default-to u0
    (get count (map-get? proof-count { product-id: product-id })))
)

;; ============================================================
;; PARTNER MANAGEMENT
;; ============================================================

;; Register a new supply-chain partner (owner only)
(define-public (register-partner
    (partner  principal)
    (name     (string-ascii 64))
    (role     (string-ascii 32)))
  (begin
    (asserts! (is-contract-owner) ERR-NOT-AUTHORIZED)
    (asserts! (is-none (map-get? partners { partner: partner })) ERR-PARTNER-EXISTS)
    (map-set partners
      { partner: partner }
      {
        name:          name,
        role:          role,
        active:        true,
        registered-at: block-height
      }
    )
    (var-set total-partners (+ (var-get total-partners) u1))
    (ok true)
  )
)

;; Deactivate a partner (owner only)
(define-public (deactivate-partner (partner principal))
  (begin
    (asserts! (is-contract-owner) ERR-NOT-AUTHORIZED)
    (match (map-get? partners { partner: partner })
      entry
        (begin
          (map-set partners { partner: partner }
            (merge entry { active: false }))
          (ok true)
        )
      ERR-PARTNER-NOT-FOUND
    )
  )
)

;; ============================================================
;; PRODUCT REGISTRATION
;; ============================================================

;; Register a new product with its cryptographic fingerprint
(define-public (register-product
    (product-id  (buff 32))
    (name        (string-ascii 128))
    (category    (string-ascii 64))
    (fingerprint (buff 64)))
  (begin
    (asserts! (is-active-partner tx-sender) ERR-NOT-AUTHORIZED)
    (asserts! (not (product-exists product-id)) ERR-PRODUCT-EXISTS)
    (map-set products
      { product-id: product-id }
      {
        name:         name,
        category:     category,
        manufacturer: tx-sender,
        fingerprint:  fingerprint,
        status:       STATUS-ACTIVE,
        custodian:    tx-sender,
        created-at:   block-height,
        updated-at:   block-height
      }
    )
    (map-set transfer-count { product-id: product-id } { count: u0 })
    (map-set proof-count    { product-id: product-id } { count: u0 })
    (var-set total-products (+ (var-get total-products) u1))
    (ok true)
  )
)

;; ============================================================
;; CUSTODY TRANSFER
;; ============================================================

;; Transfer custody of a product to another partner
(define-public (transfer-custody
    (product-id (buff 32))
    (to         principal)
    (location   (string-ascii 128))
    (notes      (string-ascii 256)))
  (let (
    (product (unwrap! (map-get? products { product-id: product-id }) ERR-PRODUCT-NOT-FOUND))
    (seq     (get-transfer-seq product-id))
  )
    ;; Caller must be current custodian and active partner
    (asserts! (is-eq tx-sender (get custodian product)) ERR-NOT-CUSTODIAN)
    (asserts! (is-active-partner tx-sender)             ERR-NOT-AUTHORIZED)
    (asserts! (is-active-partner to)                    ERR-NOT-AUTHORIZED)
    ;; Product must be active
    (asserts! (is-eq (get status product) STATUS-ACTIVE) ERR-INVALID-STATUS)
    ;; Append immutable log entry
    (map-set custody-log
      { product-id: product-id, seq: seq }
      {
        from:           tx-sender,
        to:             to,
        location:       location,
        transferred-at: block-height,
        notes:          notes
      }
    )
    ;; Update custodian and sequence counter
    (map-set products { product-id: product-id }
      (merge product { custodian: to, updated-at: block-height }))
    (map-set transfer-count { product-id: product-id } { count: (+ seq u1) })
    (ok (+ seq u1))
  )
)

;; ============================================================
;; COMPLIANCE PROOF ANCHORING
;; ============================================================

;; Anchor a zero-knowledge compliance proof on-chain
(define-public (anchor-compliance-proof
    (product-id  (buff 32))
    (proof-hash  (buff 64))
    (standard    (string-ascii 64))
    (passed      bool))
  (let (
    (product (unwrap! (map-get? products { product-id: product-id }) ERR-PRODUCT-NOT-FOUND))
    (pid     (get-proof-seq product-id))
  )
    (asserts! (is-active-partner tx-sender) ERR-NOT-AUTHORIZED)
    (map-set compliance-proofs
      { product-id: product-id, proof-id: pid }
      {
        proof-hash:  proof-hash,
        standard:    standard,
        verified-by: tx-sender,
        verified-at: block-height,
        passed:      passed
      }
    )
    (map-set proof-count { product-id: product-id } { count: (+ pid u1) })
    ;; Auto-flag product if compliance check failed
    (if (not passed)
      (map-set products { product-id: product-id }
        (merge product { status: STATUS-FLAGGED, updated-at: block-height }))
      true
    )
    (ok (+ pid u1))
  )
)

;; ============================================================
;; PRODUCT STATUS MANAGEMENT
;; ============================================================

;; Update product status (owner or current custodian)
(define-public (update-product-status
    (product-id (buff 32))
    (new-status uint))
  (let (
    (product (unwrap! (map-get? products { product-id: product-id }) ERR-PRODUCT-NOT-FOUND))
  )
    (asserts!
      (or (is-contract-owner) (is-eq tx-sender (get custodian product)))
      ERR-NOT-AUTHORIZED)
    ;; Allow valid status values only
    (asserts!
      (or
        (is-eq new-status STATUS-ACTIVE)
        (is-eq new-status STATUS-FLAGGED)
        (is-eq new-status STATUS-RECALLED)
        (is-eq new-status STATUS-RETIRED))
      ERR-INVALID-STATUS)
    (map-set products { product-id: product-id }
      (merge product { status: new-status, updated-at: block-height }))
    (ok true)
  )
)

;; ============================================================
;; READ-ONLY QUERIES
;; ============================================================

;; Get full product record
(define-read-only (get-product (product-id (buff 32)))
  (map-get? products { product-id: product-id })
)

;; Get partner record
(define-read-only (get-partner (partner principal))
  (map-get? partners { partner: partner })
)

;; Get a specific custody log entry
(define-read-only (get-custody-entry (product-id (buff 32)) (seq uint))
  (map-get? custody-log { product-id: product-id, seq: seq })
)

;; Get the total number of transfers for a product
(define-read-only (get-transfer-count (product-id (buff 32)))
  (get-transfer-seq product-id)
)

;; Get a specific compliance proof
(define-read-only (get-compliance-proof (product-id (buff 32)) (proof-id uint))
  (map-get? compliance-proofs { product-id: product-id, proof-id: proof-id })
)

;; Get the total number of compliance proofs for a product
(define-read-only (get-proof-count (product-id (buff 32)))
  (get-proof-seq product-id)
)

;; Verify a product fingerprint matches the registered value
(define-read-only (verify-fingerprint (product-id (buff 32)) (fingerprint (buff 64)))
  (match (map-get? products { product-id: product-id })
    product (ok (is-eq (get fingerprint product) fingerprint))
    ERR-PRODUCT-NOT-FOUND
  )
)

;; Check whether a product is currently compliant (status = active)
(define-read-only (is-product-compliant (product-id (buff 32)))
  (match (map-get? products { product-id: product-id })
    product (ok (is-eq (get status product) STATUS-ACTIVE))
    ERR-PRODUCT-NOT-FOUND
  )
)

;; Platform-level statistics
(define-read-only (get-platform-stats)
  (ok {
    total-products: (var-get total-products),
    total-partners:  (var-get total-partners),
    current-block:   block-height
  })
)
