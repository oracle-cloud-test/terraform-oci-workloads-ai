# INTENTIONALLY INSECURE - For IaC Security Scanner Testing Only
# Violations: Public bucket, no versioning, no encryption key, logging disabled

resource "oci_objectstorage_bucket" "insecure_public_bucket" {
  compartment_id = var.compartment_id
  name           = "ai-txn-monitoring-public-data"
  namespace      = data.oci_objectstorage_namespace.ns.namespace

  # INSECURE: Bucket is publicly readable by anyone on the internet
  access_type = "ObjectRead"

  # INSECURE: No customer-managed encryption key (uses Oracle-managed by default is acceptable,
  # but explicitly omitting kms_key_id when policy requires CMEK is a finding)
  # kms_key_id = ""  # intentionally left empty

  # INSECURE: Versioning disabled — no protection against accidental/malicious deletion
  versioning = "Disabled"

  # INSECURE: No object lifecycle policy → data retained indefinitely

  # INSECURE: No replication configured (missing DR posture)

  metadata = {
    environment = "production"
    contains    = "sensitive-transaction-data"   # labelled sensitive but exposed!
  }
}

# INSECURE: Pre-authenticated request with no expiry (effectively permanent public URL)
resource "oci_objectstorage_preauthrequest" "permanent_par" {
  namespace    = data.oci_objectstorage_namespace.ns.namespace
  bucket       = oci_objectstorage_bucket.insecure_public_bucket.name
  name         = "permanent-public-access"
  access_type  = "AnyObjectReadWrite"

  # INSECURE: Expiry far in the future (year 2099) = effectively never expires
  time_expires = "2099-12-31T00:00:00Z"
}

# INSECURE: Bucket with public write access (allows anonymous uploads)
resource "oci_objectstorage_bucket" "insecure_write_bucket" {
  compartment_id = var.compartment_id
  name           = "ai-txn-upload-open"
  namespace      = data.oci_objectstorage_namespace.ns.namespace

  # INSECURE: ObjectReadWrite allows unauthenticated writes
  access_type = "ObjectReadWrite"
  versioning  = "Disabled"
}
