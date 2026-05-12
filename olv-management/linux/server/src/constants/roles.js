// Canonical role definitions + rank ordering.
//
// Roles live both in code and in the `user_enterprise_roles.role` CHECK
// constraint (migration 013_add_root_role.sql). Keep this file aligned
// with that migration; mismatched values would silently drop a user out
// of `ADMIN_ROLES` here while the DB still let them write the role,
// stranding them.
//
// Rank ordering is used by enterprise-mgmt routes for the "I can only
// touch roles weaker than my own" rule. Higher number = more authority.

const ROLES = Object.freeze({
  ROOT: 'root',
  SUPER_ADMIN: 'super_admin',
  ADMIN: 'admin',
  MEMBER: 'member',
});

// Roles that have admin-level mutate powers on per-server resources
// (firewall, NAT, peers, subnets, …). Read access is broader.
const ADMIN_ROLES = Object.freeze([ROLES.ROOT, ROLES.SUPER_ADMIN, ROLES.ADMIN]);

const ROLE_RANK = Object.freeze({
  [ROLES.ROOT]: 4,
  [ROLES.SUPER_ADMIN]: 3,
  [ROLES.ADMIN]: 2,
  [ROLES.MEMBER]: 1,
});

function isAdmin(role) {
  return ADMIN_ROLES.includes(role);
}

function canManageRole(callerRole, targetRole) {
  return (ROLE_RANK[callerRole] || 0) > (ROLE_RANK[targetRole] || 0);
}

module.exports = { ROLES, ADMIN_ROLES, ROLE_RANK, isAdmin, canManageRole };
