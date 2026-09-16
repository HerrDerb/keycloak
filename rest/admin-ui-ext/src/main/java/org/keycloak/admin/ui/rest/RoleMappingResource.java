package org.keycloak.admin.ui.rest;

import java.util.HashSet;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.keycloak.models.GroupModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleModel;
import org.keycloak.services.resources.admin.fgap.AdminPermissionEvaluator;

public abstract class RoleMappingResource {
    protected final KeycloakSession session;
    protected final RealmModel realm;
    protected final AdminPermissionEvaluator auth;

    public RoleMappingResource(KeycloakSession session, RealmModel realm, AdminPermissionEvaluator auth) {
        this.session = session;
        this.realm = realm;
        this.auth = auth;
    }

    /**
     * Expands the given roles with their composites, recursively. Roles the caller may not view are dropped together
     * with the composites only reachable through them.
     */
    protected Stream<RoleModel> addSubRoles(Stream<RoleModel> roles) {
        return addSubRoles(roles, new HashSet<>());
    }

    private Stream<RoleModel> addSubRoles(Stream<RoleModel> roles, HashSet<RoleModel> visited) {
        List<RoleModel> roleList = roles.filter(s -> auth.roles().canView(s)).collect(Collectors.toList());
        visited.addAll(roleList);
        return Stream.concat(roleList.stream(), roleList.stream().flatMap(r -> addSubRoles(r.getCompositesStream().filter(s -> !visited.contains(s)), visited)));
    }

    /**
     * The group and all its ancestors, so that inherited group role mappings are included.
     */
    protected Stream<GroupModel> addParents(GroupModel group) {
        if (group.getParent() == null) {
            return Stream.of(group);
        }
        return Stream.concat(Stream.of(group), addParents(group.getParent()));
    }
}
