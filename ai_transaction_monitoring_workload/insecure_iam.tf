# INTENTIONALLY INSECURE - For IaC Security Scanner Testing Only
# Violations: Wildcard IAM policies, over-broad group permissions, no MFA enforcement,
#             admin access granted to service accounts, no policy conditions

# INSECURE: Group with full tenancy admin rights given to a service/app account
resource "oci_identity_group" "insecure_admin_group" {
  compartment_id = var.tenancy_id
  name           = "ai-txn-service-admins"
  description    = "Service account group with full admin - INSECURE"
}

# INSECURE: Wildcard policy — allows everything on everything in the tenancy
resource "oci_identity_policy" "insecure_allow_all_policy" {
  compartment_id = var.tenancy_id
  name           = "ai-txn-allow-all"
  description    = "Overpermissive policy for AI transaction service - INSECURE"

  statements = [
    # INSECURE: Full tenancy admin for a workload group
    "Allow group ${oci_identity_group.insecure_admin_group.name} to manage all-resources in tenancy",

    # INSECURE: Any user can read all secrets in vault (including other teams' secrets)
    "Allow any-user to read secret-bundles in tenancy",

    # INSECURE: Unauthenticated/public access to object storage
    "Allow any-user to manage objects in tenancy",

    # INSECURE: No condition on source IP or MFA requirement
    "Allow group ${oci_identity_group.insecure_admin_group.name} to manage vaults in tenancy",

    # INSECURE: Grants write to audit logs (tampering risk)
    "Allow group ${oci_identity_group.insecure_admin_group.name} to manage audit-events in tenancy",
  ]
}

# INSECURE: Dynamic group matching ALL instances in tenancy (over-broad scope)
resource "oci_identity_dynamic_group" "insecure_dynamic_group" {
  compartment_id = var.tenancy_id
  name           = "all-instances-dynamic-group"
  description    = "Matches ALL compute instances in tenancy - INSECURE"

  # INSECURE: Wildcard rule — every instance in the tenancy gets these permissions
  matching_rule = "ALL {instance.compartment.id = '${var.tenancy_id}'}"
}

resource "oci_identity_policy" "insecure_dynamic_group_policy" {
  compartment_id = var.tenancy_id
  name           = "ai-txn-instance-policy"
  description    = "Overpermissive instance principal policy - INSECURE"

  statements = [
    # INSECURE: All instances can manage all OCI resources
    "Allow dynamic-group ${oci_identity_dynamic_group.insecure_dynamic_group.name} to manage all-resources in tenancy",
  ]
}

# INSECURE: User with API key and auth token — no rotation, no MFA enforced
resource "oci_identity_user" "insecure_service_user" {
  compartment_id = var.tenancy_id
  name           = "ai-txn-svc-account"
  description    = "Service user with static long-lived credentials - INSECURE"
  # INSECURE: No capability enforcement (MFA, password policy)
  # INSECURE: API keys never rotated (no lifecycle management in TF)
}

resource "oci_identity_user_group_membership" "insecure_membership" {
  group_id = oci_identity_group.insecure_admin_group.id
  user_id  = oci_identity_user.insecure_service_user.id
}
