/*
 * Copyright 2025 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.keycloak.tests.admin.authz.fgap;

import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import jakarta.ws.rs.ForbiddenException;
import jakarta.ws.rs.client.Client;
import jakarta.ws.rs.client.Entity;
import jakarta.ws.rs.client.WebTarget;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.resource.BearerAuthFilter;
import org.keycloak.admin.client.resource.ClientScopeResource;
import org.keycloak.admin.ui.rest.model.RoleDeleteRequest;
import org.keycloak.authorization.fgap.AdminPermissionsSchema;
import org.keycloak.models.AdminRoles;
import org.keycloak.representations.idm.ClientMappingsRepresentation;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.representations.idm.ClientScopeRepresentation;
import org.keycloak.representations.idm.GroupRepresentation;
import org.keycloak.representations.idm.MappingsRepresentation;
import org.keycloak.representations.idm.RoleRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.keycloak.representations.idm.authorization.UserPolicyRepresentation;
import org.keycloak.testframework.annotations.InjectAdminClient;
import org.keycloak.testframework.annotations.InjectKeycloakUrls;
import org.keycloak.testframework.annotations.KeycloakIntegrationTest;
import org.keycloak.testframework.server.KeycloakUrls;
import org.keycloak.testframework.util.ApiUtil;

import org.junit.jupiter.api.Test;

import static org.keycloak.authorization.fgap.AdminPermissionsSchema.MANAGE;
import static org.keycloak.authorization.fgap.AdminPermissionsSchema.MANAGE_MEMBERSHIP;
import static org.keycloak.authorization.fgap.AdminPermissionsSchema.MAP_ROLE;
import static org.keycloak.authorization.fgap.AdminPermissionsSchema.MAP_ROLES;
import static org.keycloak.authorization.fgap.AdminPermissionsSchema.MAP_ROLE_CLIENT_SCOPE;
import static org.keycloak.authorization.fgap.AdminPermissionsSchema.MAP_ROLE_COMPOSITE;
import static org.keycloak.authorization.fgap.AdminPermissionsSchema.VIEW;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.hasKey;
import static org.hamcrest.Matchers.hasProperty;
import static org.hamcrest.Matchers.instanceOf;
import static org.hamcrest.Matchers.not;
import static org.junit.jupiter.api.Assertions.fail;

@KeycloakIntegrationTest
public class RoleResourceTypeEvaluationTest extends AbstractPermissionTest {

    @InjectAdminClient(mode = InjectAdminClient.Mode.MANAGED_REALM, client = "myclient", user = "myadmin")
    Keycloak realmAdminClient;

    @InjectKeycloakUrls
    KeycloakUrls keycloakUrls;

    private final String rolesType = AdminPermissionsSchema.ROLES.getType();

    @Test
    public void testMapRoleClientScopeAllRoles() {
        UserRepresentation myadmin = realm.admin().users().search("myadmin").get(0);
        UserPolicyRepresentation onlyMyAdminUserPolicy = createUserPolicy(realm, adminPermissionsClient, "Only My Admin User Policy", myadmin.getId());
        // we need to be able to list and manage client scopes
        createAllPermission(adminPermissionsClient, AdminPermissionsSchema.CLIENTS.getType(), onlyMyAdminUserPolicy, Set.of(VIEW, MANAGE));

        // create a realm role to use in scope mapping tests
        RoleRepresentation testRole = new RoleRepresentation();
        testRole.setName("testScopeRole");
        realm.admin().roles().create(testRole);
        testRole = realm.admin().roles().get("testScopeRole").toRepresentation();
        realm.cleanup().add(r -> r.roles().get("testScopeRole").remove());

        // create a client-scope
        ClientScopeRepresentation clientScope = new ClientScopeRepresentation();
        clientScope.setName("my-client-scope");
        clientScope.setProtocol("openid-connect");
        try (Response response = realm.admin().clientScopes().create(clientScope)) {
            assertThat(response.getStatus(), equalTo(Response.Status.CREATED.getStatusCode()));
            clientScope.setId(ApiUtil.getCreatedId(response));
            realm.cleanup().add(r -> r.clientScopes().get(clientScope.getId()).remove());
        }

        // we don't have permissions to map roles to a client scope so the list of available roles should be empty
        ClientScopeResource clientScopeResource = realmAdminClient.realm(realm.getName()).clientScopes().get(clientScope.getId());
        List<RoleRepresentation> availableRoles = clientScopeResource.getScopeMappings().realmLevel().listAvailable();
        assertThat(availableRoles, empty());

        // adding a realm-level scope mapping should also fail without MAP_ROLE_CLIENT_SCOPE permission
        try {
            clientScopeResource.getScopeMappings().realmLevel().add(List.of(testRole));
            fail("Expected ForbiddenException when adding realm scope mapping without MAP_ROLE_CLIENT_SCOPE permission");
        } catch (Exception ex) {
            assertThat(ex, instanceOf(ForbiddenException.class));
        }

        // grant the permission to map all roles to client scopes
        createAllPermission(adminPermissionsClient, rolesType, onlyMyAdminUserPolicy, Set.of(MAP_ROLE_CLIENT_SCOPE));

        availableRoles = clientScopeResource.getScopeMappings().realmLevel().listAvailable();
        assertThat(availableRoles, not(empty()));

        // adding the scope mapping should now succeed
        clientScopeResource.getScopeMappings().realmLevel().add(List.of(testRole));

        // verify the role was added
        List<RoleRepresentation> mappedRoles = clientScopeResource.getScopeMappings().realmLevel().listAll();
        assertThat(mappedRoles, not(empty()));

        // removing the scope mapping should also succeed
        clientScopeResource.getScopeMappings().realmLevel().remove(List.of(testRole));
    }

    @Test
    public void testMapRoleClientScopeWriteDeniedWithoutPermission() {
        UserRepresentation myadmin = realm.admin().users().search("myadmin").get(0);
        UserPolicyRepresentation onlyMyAdminUserPolicy = createUserPolicy(realm, adminPermissionsClient, "Only My Admin User Policy", myadmin.getId());
        createAllPermission(adminPermissionsClient, AdminPermissionsSchema.CLIENTS.getType(), onlyMyAdminUserPolicy, Set.of(VIEW, MANAGE));

        // create two realm roles
        RoleRepresentation allowedRole = new RoleRepresentation();
        allowedRole.setName("allowedRole");
        realm.admin().roles().create(allowedRole);
        allowedRole = realm.admin().roles().get("allowedRole").toRepresentation();
        realm.cleanup().add(r -> r.roles().get("allowedRole").remove());

        RoleRepresentation deniedRole = new RoleRepresentation();
        deniedRole.setName("deniedRole");
        realm.admin().roles().create(deniedRole);
        deniedRole = realm.admin().roles().get("deniedRole").toRepresentation();
        realm.cleanup().add(r -> r.roles().get("deniedRole").remove());

        // create a client-scope
        ClientScopeRepresentation clientScope = new ClientScopeRepresentation();
        clientScope.setName("test-client-scope");
        clientScope.setProtocol("openid-connect");
        try (Response response = realm.admin().clientScopes().create(clientScope)) {
            assertThat(response.getStatus(), equalTo(Response.Status.CREATED.getStatusCode()));
            clientScope.setId(ApiUtil.getCreatedId(response));
            realm.cleanup().add(r -> r.clientScopes().get(clientScope.getId()).remove());
        }

        // grant MAP_ROLE_CLIENT_SCOPE only for a specific role
        createPermission(adminPermissionsClient, allowedRole.getId(), rolesType, Set.of(MAP_ROLE_CLIENT_SCOPE), onlyMyAdminUserPolicy);

        ClientScopeResource clientScopeResource = realmAdminClient.realm(realm.getName()).clientScopes().get(clientScope.getId());

        // adding the allowed role should succeed
        clientScopeResource.getScopeMappings().realmLevel().add(List.of(allowedRole));

        // adding the denied role should fail
        try {
            clientScopeResource.getScopeMappings().realmLevel().add(List.of(deniedRole));
            fail("Expected ForbiddenException when adding scope mapping for a role without MAP_ROLE_CLIENT_SCOPE permission");
        } catch (Exception ex) {
            assertThat(ex, instanceOf(ForbiddenException.class));
        }

        // removing the allowed role should succeed
        clientScopeResource.getScopeMappings().realmLevel().remove(List.of(allowedRole));

        // add the denied role as super admin so we can test that a limited admin can't remove it
        realm.admin().clientScopes().get(clientScope.getId()).getScopeMappings().realmLevel().add(List.of(deniedRole));

        // removing the denied role should fail for the limited admin
        try {
            clientScopeResource.getScopeMappings().realmLevel().remove(List.of(deniedRole));
            fail("Expected ForbiddenException when removing scope mapping for a role without MAP_ROLE_CLIENT_SCOPE permission");
        } catch (Exception ex) {
            assertThat(ex, instanceOf(ForbiddenException.class));
        }
    }

    @Test
    public void testMapRoleClientScopeClientLevelRoles() {
        UserRepresentation myadmin = realm.admin().users().search("myadmin").get(0);
        UserPolicyRepresentation onlyMyAdminUserPolicy = createUserPolicy(realm, adminPermissionsClient, "Only My Admin User Policy", myadmin.getId());
        createAllPermission(adminPermissionsClient, AdminPermissionsSchema.CLIENTS.getType(), onlyMyAdminUserPolicy, Set.of(VIEW, MANAGE));

        // create a client role
        ClientRepresentation myclient = realm.admin().clients().findByClientId("myclient").get(0);
        RoleRepresentation clientRole = new RoleRepresentation();
        clientRole.setName("testClientRole");
        clientRole.setClientRole(true);
        realm.admin().clients().get(myclient.getId()).roles().create(clientRole);
        clientRole = realm.admin().clients().get(myclient.getId()).roles().get("testClientRole").toRepresentation();

        // create a client-scope
        ClientScopeRepresentation clientScope = new ClientScopeRepresentation();
        clientScope.setName("test-client-scope-for-client-roles");
        clientScope.setProtocol("openid-connect");
        try (Response response = realm.admin().clientScopes().create(clientScope)) {
            assertThat(response.getStatus(), equalTo(Response.Status.CREATED.getStatusCode()));
            clientScope.setId(ApiUtil.getCreatedId(response));
            realm.cleanup().add(r -> r.clientScopes().get(clientScope.getId()).remove());
        }

        ClientScopeResource clientScopeResource = realmAdminClient.realm(realm.getName()).clientScopes().get(clientScope.getId());

        // adding a client-level scope mapping should fail without MAP_ROLE_CLIENT_SCOPE permission
        try {
            clientScopeResource.getScopeMappings().clientLevel(myclient.getId()).add(List.of(clientRole));
            fail("Expected ForbiddenException when adding client scope mapping without MAP_ROLE_CLIENT_SCOPE permission");
        } catch (Exception ex) {
            assertThat(ex, instanceOf(ForbiddenException.class));
        }

        // grant MAP_ROLE_CLIENT_SCOPE for all roles
        createAllPermission(adminPermissionsClient, rolesType, onlyMyAdminUserPolicy, Set.of(MAP_ROLE_CLIENT_SCOPE));

        // adding the client-level scope mapping should now succeed
        clientScopeResource.getScopeMappings().clientLevel(myclient.getId()).add(List.of(clientRole));

        // removing the client-level scope mapping should also succeed
        clientScopeResource.getScopeMappings().clientLevel(myclient.getId()).remove(List.of(clientRole));
    }

    @Test
    public void testMapCompositeRoleAllRoles() {
        UserRepresentation myadmin = realm.admin().users().search("myadmin").get(0);

        // create a role and sub-role
        RoleRepresentation role = new RoleRepresentation();
        role.setName("myRole");
        realm.admin().roles().create(role);
        realm.cleanup().add(r -> r.roles().get("myRole").remove());

        RoleRepresentation subRole = new RoleRepresentation();
        subRole.setName("mySubRole");
        realm.admin().roles().create(subRole);
        subRole = realm.admin().roles().get("mySubRole").toRepresentation();
        realm.cleanup().add(r -> r.roles().get("mySubRole").remove());

        // the following operation should fail as the permission wasn't granted yet
        try {
            realmAdminClient.realm(realm.getName()).roles().get("myRole").addComposites(List.of(subRole));
            fail("Expected exception wasn't thrown.");
        } catch (Exception ex) {
            assertThat(ex, instanceOf(ForbiddenException.class));
        }

        String clientId = realm.admin().clients().findByClientId("realm-management").get(0).getId();
        RoleRepresentation manageRealmRole = realm.admin().clients().get(clientId).roles().get("manage-realm").toRepresentation();
        realm.admin().users().get(myadmin.getId()).roles().clientLevel(clientId).add(List.of(manageRealmRole));
        realmAdminClient.tokenManager().grantToken();

        UserPolicyRepresentation onlyMyAdminUserPolicy = createUserPolicy(realm, adminPermissionsClient, "Only My Admin User Policy", myadmin.getId());
        createAllPermission(adminPermissionsClient, rolesType, onlyMyAdminUserPolicy, Set.of(MAP_ROLE_COMPOSITE));

        realmAdminClient.realm(realm.getName()).roles().get("myRole").addComposites(List.of(subRole));
    }

    @Test
    public void testDeleteCompositeRoleRequiresMapCompositePermission() {
        UserRepresentation myadmin = realm.admin().users().search("myadmin").get(0);
        ClientRepresentation myclient = realm.admin().clients().findByClientId("myclient").get(0);
        String myclientId = myclient.getId();

        // create client sub-roles on myclient (using client roles avoids manage-realm bypassing canMapComposite)
        RoleRepresentation allowedSubRole = new RoleRepresentation();
        allowedSubRole.setName("allowedSubRole");
        realm.admin().clients().get(myclientId).roles().create(allowedSubRole);
        allowedSubRole = realm.admin().clients().get(myclientId).roles().get("allowedSubRole").toRepresentation();

        RoleRepresentation restrictedSubRole = new RoleRepresentation();
        restrictedSubRole.setName("restrictedSubRole");
        realm.admin().clients().get(myclientId).roles().create(restrictedSubRole);
        restrictedSubRole = realm.admin().clients().get(myclientId).roles().get("restrictedSubRole").toRepresentation();

        // create parent realm role (for endpoint 1) and parent client role (for endpoints 2 & 3)
        RoleRepresentation parentRealmRole = new RoleRepresentation();
        parentRealmRole.setName("parentRealmRole");
        realm.admin().roles().create(parentRealmRole);
        parentRealmRole = realm.admin().roles().get("parentRealmRole").toRepresentation();
        realm.cleanup().add(r -> r.roles().get("parentRealmRole").remove());

        RoleRepresentation parentClientRole = new RoleRepresentation();
        parentClientRole.setName("parentClientRole");
        realm.admin().clients().get(myclientId).roles().create(parentClientRole);
        parentClientRole = realm.admin().clients().get(myclientId).roles().get("parentClientRole").toRepresentation();

        // grant myadmin manage-realm (required for realm role endpoint's requireManage(RealmModel))
        String realmMgmtId = realm.admin().clients().findByClientId("realm-management").get(0).getId();
        RoleRepresentation manageRealmRole = realm.admin().clients().get(realmMgmtId).roles().get("manage-realm").toRepresentation();
        realm.admin().users().get(myadmin.getId()).roles().clientLevel(realmMgmtId).add(List.of(manageRealmRole));
        realmAdminClient.tokenManager().grantToken();

        // grant FGAP MANAGE on myclient (for client role endpoints' requireManage)
        UserPolicyRepresentation policy = createUserPolicy(realm, adminPermissionsClient, "Only My Admin User Policy", myadmin.getId());
        createPermission(adminPermissionsClient, myclientId, AdminPermissionsSchema.CLIENTS_RESOURCE_TYPE, Set.of(MANAGE), policy);

        // grant MAP_ROLE_COMPOSITE only on allowedSubRole
        createPermission(adminPermissionsClient, allowedSubRole.getId(), rolesType, Set.of(MAP_ROLE_COMPOSITE), policy);

        // as full admin, add both sub-roles as composites of both parent roles
        realm.admin().roles().get("parentRealmRole").addComposites(List.of(allowedSubRole, restrictedSubRole));
        realm.admin().clients().get(myclientId).roles().get("parentClientRole").addComposites(List.of(allowedSubRole, restrictedSubRole));

        // --- Endpoint 1: DELETE /admin/realms/{realm}/roles/{role-name}/composites ---
        try {
            realmAdminClient.realm(realm.getName()).roles().get("parentRealmRole").deleteComposites(List.of(restrictedSubRole));
            fail("Should not be able to delete composite without MAP_ROLE_COMPOSITE permission");
        } catch (Exception ex) {
            assertThat(ex, instanceOf(ForbiddenException.class));
        }
        realmAdminClient.realm(realm.getName()).roles().get("parentRealmRole").deleteComposites(List.of(allowedSubRole));

        // --- Endpoint 3: DELETE /admin/realms/{realm}/clients/{id}/roles/{role-name}/composites ---
        try {
            realmAdminClient.realm(realm.getName()).clients().get(myclientId).roles().get("parentClientRole").deleteComposites(List.of(restrictedSubRole));
            fail("Should not be able to delete composite without MAP_ROLE_COMPOSITE permission");
        } catch (Exception ex) {
            assertThat(ex, instanceOf(ForbiddenException.class));
        }
        realmAdminClient.realm(realm.getName()).clients().get(myclientId).roles().get("parentClientRole").deleteComposites(List.of(allowedSubRole));

        // --- Endpoint 2: DELETE /admin/realms/{realm}/roles-by-id/{role-id}/composites ---
        // re-add allowedSubRole as composite (was removed above)
        realm.admin().clients().get(myclientId).roles().get("parentClientRole").addComposites(List.of(allowedSubRole));

        try {
            realmAdminClient.realm(realm.getName()).rolesById().deleteComposites(parentClientRole.getId(), List.of(restrictedSubRole));
            fail("Should not be able to delete composite without MAP_ROLE_COMPOSITE permission");
        } catch (Exception ex) {
            assertThat(ex, instanceOf(ForbiddenException.class));
        }
        realmAdminClient.realm(realm.getName()).rolesById().deleteComposites(parentClientRole.getId(), List.of(allowedSubRole));
    }

    @Test
    public void testMapRoleOnlySpecificRole() {
        UserRepresentation myadmin = realm.admin().users().search("myadmin").get(0);

        // create some roles
        RoleRepresentation role = new RoleRepresentation();
        role.setName("myRole");
        realm.admin().roles().create(role);
        role = realm.admin().roles().get("myRole").toRepresentation();
        realm.cleanup().add(r -> r.roles().get("myRole").remove());

        RoleRepresentation otherRole = new RoleRepresentation();
        otherRole.setName("otherRole");
        realm.admin().roles().create(otherRole);
        otherRole = realm.admin().roles().get("otherRole").toRepresentation();
        realm.cleanup().add(r -> r.roles().get("otherRole").remove());

        // the following operation should fail as the permission wasn't granted yet
        try {
            realmAdminClient.realm(realm.getName()).users().get(myadmin.getId()).roles().realmLevel().add(List.of(role));
            fail("Expected exception wasn't thrown.");
        } catch (Exception ex) {
            assertThat(ex, instanceOf(ForbiddenException.class));
        }

        // create required permissions
        UserPolicyRepresentation onlyMyAdminUserPolicy = createUserPolicy(realm, adminPermissionsClient, "Only My Admin User Policy", myadmin.getId());
        createPermission(adminPermissionsClient, role.getId(), rolesType, Set.of(MAP_ROLE), onlyMyAdminUserPolicy);
        createPermission(adminPermissionsClient, myadmin.getId(), AdminPermissionsSchema.USERS_RESOURCE_TYPE, Set.of(MAP_ROLES), onlyMyAdminUserPolicy);

        // should pass
        realmAdminClient.realm(realm.getName()).users().get(myadmin.getId()).roles().realmLevel().add(List.of(role));

        // the following operation should fail as there is no permission for "otherRole"
        try {
            realmAdminClient.realm(realm.getName()).users().get(myadmin.getId()).roles().realmLevel().add(List.of(otherRole));
            fail("Expected exception wasn't thrown.");
        } catch (Exception ex) {
            assertThat(ex, instanceOf(ForbiddenException.class));
        }
    }

    @Test
    public void testMappingAdminRoles() {
        UserRepresentation myadmin = realm.admin().users().search("myadmin").get(0);
        ClientRepresentation realmManagement = realm.admin().clients().findByClientId("realm-management").get(0);
        RoleRepresentation createClientRole = realm.admin().clients().get(realmManagement.getId()).roles().get(AdminRoles.CREATE_CLIENT).toRepresentation();

        // create permission to map roles from all clients and to all users
        UserPolicyRepresentation onlyMyAdminUserPolicy = createUserPolicy(realm, adminPermissionsClient, "Only My Admin User Policy", myadmin.getId());
        createAllPermission(adminPermissionsClient, AdminPermissionsSchema.CLIENTS_RESOURCE_TYPE, onlyMyAdminUserPolicy, Set.of(MAP_ROLES));
        createAllPermission(adminPermissionsClient, AdminPermissionsSchema.USERS_RESOURCE_TYPE, onlyMyAdminUserPolicy, Set.of(MAP_ROLES));

        // create a role
        RoleRepresentation role = new RoleRepresentation();
        role.setName("myRole");
        ClientRepresentation myclient = realm.admin().clients().findByClientId("myclient").get(0);
        realm.admin().clients().get(myclient.getId()).roles().create(role);
        role = realm.admin().clients().get(myclient.getId()).roles().get("myRole").toRepresentation();

        // should pass
        realmAdminClient.realm(realm.getName()).users().get(myadmin.getId()).roles().clientLevel(myclient.getId()).add(List.of(role));

        // should fail as it is admin role and myadmin does not have master realm admin role assigned
        try {
            realmAdminClient.realm(realm.getName()).users().get(myadmin.getId()).roles().clientLevel(realmManagement.getId())
                    .add(List.of(createClientRole));
            fail("Expected exception wasn't thrown.");
        } catch (Exception ex) {
            assertThat(ex, instanceOf(ForbiddenException.class));
        }

        RoleRepresentation realmAdminRole = realm.admin().clients().get(realmManagement.getId()).roles().get(AdminRoles.REALM_ADMIN).toRepresentation();
        realm.admin().users().get(myadmin.getId()).roles().clientLevel(realmManagement.getId()).add(List.of(realmAdminRole));
        // should pass, user is a realm admin
        realmAdminClient.realm(realm.getName()).users().get(myadmin.getId()).roles().clientLevel(realmManagement.getId())
                .add(List.of(createClientRole));
    }

    @Test
    public void testUiExtRoleMappingDeleteRespectsPerRolePermission() {
        UserRepresentation myadmin = realm.admin().users().search("myadmin").get(0);
        UserRepresentation targetUser = createUser("targetUser");

        RoleRepresentation allowedRole = new RoleRepresentation();
        allowedRole.setName("allowedRole");
        realm.admin().roles().create(allowedRole);
        allowedRole = realm.admin().roles().get("allowedRole").toRepresentation();
        realm.cleanup().add(r -> r.roles().get("allowedRole").remove());

        RoleRepresentation restrictedRole = new RoleRepresentation();
        restrictedRole.setName("restrictedRole");
        realm.admin().roles().create(restrictedRole);
        restrictedRole = realm.admin().roles().get("restrictedRole").toRepresentation();
        realm.cleanup().add(r -> r.roles().get("restrictedRole").remove());

        // assign both roles to the target user (as realm admin)
        realm.admin().users().get(targetUser.getId()).roles().realmLevel().add(List.of(allowedRole, restrictedRole));

        // grant myadmin user-level MAP_ROLES on the target user and role-level MAP_ROLE only for allowedRole
        UserPolicyRepresentation policy = createUserPolicy(realm, adminPermissionsClient, "Only My Admin User Policy", myadmin.getId());
        createPermission(adminPermissionsClient, targetUser.getId(), AdminPermissionsSchema.USERS_RESOURCE_TYPE, Set.of(MAP_ROLES), policy);
        createPermission(adminPermissionsClient, allowedRole.getId(), rolesType, Set.of(MAP_ROLE), policy);

        try (Client httpClient = Keycloak.getClientProvider().newRestEasyClient(null, null, true)) {
            WebTarget target = httpClient.target(keycloakUrls.getBaseUrl().toString())
                    .path("admin").path("realms").path(realm.getName())
                    .path("ui-ext").path("role-mapping-delete").path("users").path(targetUser.getId())
                    .register(new BearerAuthFilter(realmAdminClient.tokenManager()));

            // deleting restrictedRole should be forbidden
            Response response = target.request(MediaType.APPLICATION_JSON)
                    .post(Entity.json(List.of(new RoleDeleteRequest(restrictedRole.getId(), restrictedRole.getName(), null))));
            assertThat(response.getStatus(), equalTo(Response.Status.FORBIDDEN.getStatusCode()));

            // deleting allowedRole should succeed
            response = target.request(MediaType.APPLICATION_JSON)
                    .post(Entity.json(List.of(new RoleDeleteRequest(allowedRole.getId(), allowedRole.getName(), null))));
            assertThat(response.getStatus(), equalTo(Response.Status.NO_CONTENT.getStatusCode()));
        }
    }

    @Test
    public void testUiExtGroupRoleMappingDeleteRespectsPerRolePermission() {
        UserRepresentation myadmin = realm.admin().users().search("myadmin").get(0);
        GroupRepresentation group = createGroup("testGroup");

        RoleRepresentation allowedRole = new RoleRepresentation();
        allowedRole.setName("allowedRole");
        realm.admin().roles().create(allowedRole);
        allowedRole = realm.admin().roles().get("allowedRole").toRepresentation();
        realm.cleanup().add(r -> r.roles().get("allowedRole").remove());

        RoleRepresentation restrictedRole = new RoleRepresentation();
        restrictedRole.setName("restrictedRole");
        realm.admin().roles().create(restrictedRole);
        restrictedRole = realm.admin().roles().get("restrictedRole").toRepresentation();
        realm.cleanup().add(r -> r.roles().get("restrictedRole").remove());

        // assign both roles to the group (as realm admin)
        realm.admin().groups().group(group.getId()).roles().realmLevel().add(List.of(allowedRole, restrictedRole));

        // grant myadmin group-level MANAGE_MEMBERSHIP and role-level MAP_ROLE only for allowedRole
        UserPolicyRepresentation policy = createUserPolicy(realm, adminPermissionsClient, "Only My Admin User Policy", myadmin.getId());
        createGroupPermission(group, Set.of(MANAGE_MEMBERSHIP), policy);
        createPermission(adminPermissionsClient, allowedRole.getId(), rolesType, Set.of(MAP_ROLE), policy);

        try (Client httpClient = Keycloak.getClientProvider().newRestEasyClient(null, null, true)) {
            WebTarget target = httpClient.target(keycloakUrls.getBaseUrl().toString())
                    .path("admin").path("realms").path(realm.getName())
                    .path("ui-ext").path("role-mapping-delete").path("groups").path(group.getId())
                    .register(new BearerAuthFilter(realmAdminClient.tokenManager()));

            // deleting restrictedRole should be forbidden
            Response response = target.request(MediaType.APPLICATION_JSON)
                    .post(Entity.json(List.of(new RoleDeleteRequest(restrictedRole.getId(), restrictedRole.getName(), null))));
            assertThat(response.getStatus(), equalTo(Response.Status.FORBIDDEN.getStatusCode()));

            // deleting allowedRole should succeed
            response = target.request(MediaType.APPLICATION_JSON)
                    .post(Entity.json(List.of(new RoleDeleteRequest(allowedRole.getId(), allowedRole.getName(), null))));
            assertThat(response.getStatus(), equalTo(Response.Status.NO_CONTENT.getStatusCode()));
        }
    }

    /**
     * A delegated administrator that may assign a realm role must also see that the role is assigned, otherwise the
     * role can be granted but never reviewed or removed. A role the administrator holds no permission on stays hidden.
     *
     * @see <a href="https://github.com/keycloak/keycloak/issues/52727">#52727</a>
     */
    @Test
    public void testAssignedRealmRoleVisibleWithMapRolePermission() {
        UserRepresentation myadmin = realm.admin().users().search("myadmin").get(0);
        UserRepresentation targetUser = createUser("targetUser");
        RoleRepresentation mappableRole = createRealmRole("MAPPABLE_REALM_ROLE");
        RoleRepresentation hiddenRole = createRealmRole("HIDDEN_REALM_ROLE");
        realm.admin().users().get(targetUser.getId()).roles().realmLevel().add(List.of(mappableRole, hiddenRole));

        UserPolicyRepresentation policy = createUserPolicy(realm, adminPermissionsClient, "Only My Admin User Policy", myadmin.getId());
        createPermission(adminPermissionsClient, targetUser.getId(), AdminPermissionsSchema.USERS_RESOURCE_TYPE, Set.of(VIEW), policy);
        createPermission(adminPermissionsClient, mappableRole.getId(), rolesType, Set.of(MAP_ROLE), policy);

        // GET /users/{id}/role-mappings
        MappingsRepresentation mappings = realmAdminClient.realm(realm.getName()).users().get(targetUser.getId()).roles().getAll();
        assertThat(mappings.getRealmMappings(), hasItem(hasProperty("name", equalTo("MAPPABLE_REALM_ROLE"))));
        assertThat(mappings.getRealmMappings(), not(hasItem(hasProperty("name", equalTo("HIDDEN_REALM_ROLE")))));

        // the console reads the inherited list from ui-ext, so both endpoints have to agree
        String body = getUiExtEndpoint("effective-roles-all/users/" + targetUser.getId());
        assertThat(body, containsString("MAPPABLE_REALM_ROLE"));
        assertThat(body, not(containsString("HIDDEN_REALM_ROLE")));

        // the console follows the role name to GET /roles-by-id/{id}, which has to agree with the list
        assertThat(realmAdminClient.realm(realm.getName()).rolesById().getRole(mappableRole.getId()).getName(), equalTo("MAPPABLE_REALM_ROLE"));
        try {
            realmAdminClient.realm(realm.getName()).rolesById().getRole(hiddenRole.getId());
            fail("Expected ForbiddenException for a realm role without any permission");
        } catch (Exception ex) {
            assertThat(ex, instanceOf(ForbiddenException.class));
        }
    }

    /**
     * Only a permission granted on the role itself makes a client role of a hidden client visible. The manage-users
     * role lets an administrator assign any role, but it must not disclose clients the administrator cannot view.
     *
     * @see <a href="https://github.com/keycloak/keycloak/issues/50581">#50581</a>
     */
    @Test
    public void testAssignedClientRoleVisibleOnlyWithMapRolePermission() {
        UserRepresentation myadmin = realm.admin().users().search("myadmin").get(0);
        UserRepresentation targetUser = createUser("targetUser");
        ClientRepresentation mappableClient = createClient("mappable-client");
        ClientRepresentation secretClient = createClient("secret-client");
        RoleRepresentation mappableRole = createClientRole(mappableClient, "MAPPABLE_CLIENT_ROLE");
        RoleRepresentation siblingRole = createClientRole(mappableClient, "SIBLING_CLIENT_ROLE");
        RoleRepresentation secretRole = createClientRole(secretClient, "SECRET_CLIENT_ROLE");
        realm.admin().users().get(targetUser.getId()).roles().clientLevel(mappableClient.getId()).add(List.of(mappableRole, siblingRole));
        realm.admin().users().get(targetUser.getId()).roles().clientLevel(secretClient.getId()).add(List.of(secretRole));

        UserPolicyRepresentation policy = createUserPolicy(realm, adminPermissionsClient, "Only My Admin User Policy", myadmin.getId());
        createPermission(adminPermissionsClient, targetUser.getId(), AdminPermissionsSchema.USERS_RESOURCE_TYPE, Set.of(VIEW), policy);
        createPermission(adminPermissionsClient, mappableRole.getId(), rolesType, Set.of(MAP_ROLE), policy);

        // manage-users lets myadmin assign every role, but grants no view on any client
        String realmMgmtId = realm.admin().clients().findByClientId("realm-management").get(0).getId();
        RoleRepresentation manageUsersRole = realm.admin().clients().get(realmMgmtId).roles().get(AdminRoles.MANAGE_USERS).toRepresentation();
        realm.admin().users().get(myadmin.getId()).roles().clientLevel(realmMgmtId).add(List.of(manageUsersRole));
        realmAdminClient.tokenManager().grantToken();

        // GET /users/{id}/role-mappings
        MappingsRepresentation mappings = realmAdminClient.realm(realm.getName()).users().get(targetUser.getId()).roles().getAll();
        Map<String, ClientMappingsRepresentation> clientMappings = mappings.getClientMappings();
        assertThat(clientMappings, hasKey("mappable-client"));
        assertThat(clientMappings.get("mappable-client").getMappings(), hasItem(hasProperty("name", equalTo("MAPPABLE_CLIENT_ROLE"))));
        assertThat(clientMappings.get("mappable-client").getMappings(), not(hasItem(hasProperty("name", equalTo("SIBLING_CLIENT_ROLE")))));
        assertThat(clientMappings, not(hasKey("secret-client")));

        // GET /ui-ext/effective-roles/users/{id} and /ui-ext/effective-roles-all/users/{id}
        for (String subPath : List.of("effective-roles/users/", "effective-roles-all/users/")) {
            String body = getUiExtEndpoint(subPath + targetUser.getId());
            assertThat(body, containsString("MAPPABLE_CLIENT_ROLE"));
            assertThat(body, not(containsString("SIBLING_CLIENT_ROLE")));
            assertThat(body, not(containsString("secret-client")));
        }
    }

    /**
     * Composite membership is granted with MAP_ROLE_COMPOSITE, so that scope has to make the child role visible in the
     * composite listings of the admin API and ui-ext alike.
     */
    @Test
    public void testCompositeChildVisibleWithMapRoleCompositePermission() {
        UserRepresentation myadmin = realm.admin().users().search("myadmin").get(0);
        ClientRepresentation visibleClient = createClient("visible-client");
        ClientRepresentation secretClient = createClient("secret-client");
        RoleRepresentation parent = createClientRole(visibleClient, "VISIBLE_PARENT");
        RoleRepresentation mappableChild = createClientRole(secretClient, "MAPPABLE_CHILD");
        RoleRepresentation secretChild = createClientRole(secretClient, "SECRET_CHILD");
        realm.admin().clients().get(visibleClient.getId()).roles().get("VISIBLE_PARENT").addComposites(List.of(mappableChild, secretChild));

        UserPolicyRepresentation policy = createUserPolicy(realm, adminPermissionsClient, "Only My Admin User Policy", myadmin.getId());
        createPermission(adminPermissionsClient, visibleClient.getId(), AdminPermissionsSchema.CLIENTS_RESOURCE_TYPE, Set.of(VIEW), policy);
        createPermission(adminPermissionsClient, mappableChild.getId(), rolesType, Set.of(MAP_ROLE_COMPOSITE), policy);

        // GET /roles-by-id/{id}/composites
        List<String> composites = realmAdminClient.realm(realm.getName()).rolesById().getRoleComposites(parent.getId())
                .stream().map(RoleRepresentation::getName).toList();
        assertThat(composites, hasItem("MAPPABLE_CHILD"));
        assertThat(composites, not(hasItem("SECRET_CHILD")));

        // GET /ui-ext/role-mappings/roles/{id} and /ui-ext/effective-roles-all/roles/{id}
        for (String subPath : List.of("role-mappings/roles/", "effective-roles-all/roles/")) {
            String body = getUiExtEndpoint(subPath + parent.getId());
            assertThat(body, containsString("MAPPABLE_CHILD"));
            assertThat(body, not(containsString("SECRET_CHILD")));
        }
    }

    @Test
    public void testUiExtEndpointsFilterHiddenCompositeRoles() {
        UserRepresentation myadmin = realm.admin().users().search("myadmin").get(0);
        UserRepresentation targetUser = createUser("targetUser");

        ClientRepresentation visibleClient = new ClientRepresentation();
        visibleClient.setClientId("visible-client");
        try (Response response = realm.admin().clients().create(visibleClient)) {
            visibleClient.setId(ApiUtil.getCreatedId(response));
        }

        ClientRepresentation secretClient = new ClientRepresentation();
        secretClient.setClientId("secret-client");
        try (Response response = realm.admin().clients().create(secretClient)) {
            secretClient.setId(ApiUtil.getCreatedId(response));
        }

        RoleRepresentation visibleChild = new RoleRepresentation();
        visibleChild.setName("VISIBLE_CHILD");
        realm.admin().clients().get(visibleClient.getId()).roles().create(visibleChild);
        visibleChild = realm.admin().clients().get(visibleClient.getId()).roles().get("VISIBLE_CHILD").toRepresentation();

        RoleRepresentation secretChild = new RoleRepresentation();
        secretChild.setName("SECRET_CHILD");
        realm.admin().clients().get(secretClient.getId()).roles().create(secretChild);
        secretChild = realm.admin().clients().get(secretClient.getId()).roles().get("SECRET_CHILD").toRepresentation();

        RoleRepresentation visibleParent = new RoleRepresentation();
        visibleParent.setName("VISIBLE_PARENT");
        realm.admin().clients().get(visibleClient.getId()).roles().create(visibleParent);
        visibleParent = realm.admin().clients().get(visibleClient.getId()).roles().get("VISIBLE_PARENT").toRepresentation();
        realm.admin().clients().get(visibleClient.getId()).roles().get("VISIBLE_PARENT").addComposites(List.of(visibleChild, secretChild));

        realm.admin().users().get(targetUser.getId()).roles().clientLevel(visibleClient.getId()).add(List.of(visibleParent));
        realm.admin().users().get(targetUser.getId()).roles().clientLevel(secretClient.getId()).add(List.of(secretChild));

        UserPolicyRepresentation policy = createUserPolicy(realm, adminPermissionsClient, "Only My Admin User Policy", myadmin.getId());
        createPermission(adminPermissionsClient, visibleClient.getId(), AdminPermissionsSchema.CLIENTS_RESOURCE_TYPE, Set.of(VIEW), policy);
        createPermission(adminPermissionsClient, targetUser.getId(), AdminPermissionsSchema.USERS_RESOURCE_TYPE, Set.of(VIEW), policy);

        try (Client httpClient = Keycloak.getClientProvider().newRestEasyClient(null, null, true)) {
            String baseUiExtPath = keycloakUrls.getBaseUrl().toString();
            BearerAuthFilter bearerAuth = new BearerAuthFilter(realmAdminClient.tokenManager());

            // RoleCompositeResource: GET /ui-ext/role-mappings/roles/{id}
            String body = getUiExtEndpoint(httpClient, baseUiExtPath, realm.getName(),
                    "role-mappings/roles/" + visibleParent.getId(), bearerAuth);
            assertThat("Visible child role should be present", body, containsString("VISIBLE_CHILD"));
            assertThat("Secret child role should be filtered out", body, not(containsString("SECRET_CHILD")));
            assertThat("Secret client should not be disclosed", body, not(containsString("secret-client")));

            // EffectiveRoleMappingResource: GET /ui-ext/effective-roles/users/{id}
            body = getUiExtEndpoint(httpClient, baseUiExtPath, realm.getName(),
                    "effective-roles/users/" + targetUser.getId(), bearerAuth);
            assertThat("Visible child role should be present", body, containsString("VISIBLE_CHILD"));
            assertThat("Secret child role should be filtered out", body, not(containsString("SECRET_CHILD")));
            assertThat("Secret client should not be disclosed", body, not(containsString("secret-client")));

            // AllEffectiveRoleMappingResource: GET /ui-ext/effective-roles-all/roles/{id}
            body = getUiExtEndpoint(httpClient, baseUiExtPath, realm.getName(),
                    "effective-roles-all/roles/" + visibleParent.getId(), bearerAuth);
            assertThat("Visible parent role should be present", body, containsString("VISIBLE_PARENT"));
            assertThat("Visible child role should be present", body, containsString("VISIBLE_CHILD"));
            assertThat("Secret child role should be filtered out", body, not(containsString("SECRET_CHILD")));
            assertThat("Secret client should not be disclosed", body, not(containsString("secret-client")));

            // AllEffectiveRoleMappingResource: GET /ui-ext/effective-roles-all/users/{id}
            body = getUiExtEndpoint(httpClient, baseUiExtPath, realm.getName(),
                    "effective-roles-all/users/" + targetUser.getId(), bearerAuth);
            assertThat("Visible child role should be present", body, containsString("VISIBLE_CHILD"));
            assertThat("Directly mapped secret role should be filtered out", body, not(containsString("SECRET_CHILD")));
            assertThat("Secret client should not be disclosed", body, not(containsString("secret-client")));
        }
    }

    @Test
    public void testAdminApiCompositesFilterHiddenClientRoles() {
        UserRepresentation myadmin = realm.admin().users().search("myadmin").get(0);

        ClientRepresentation visibleClient = new ClientRepresentation();
        visibleClient.setClientId("visible-client");
        try (Response response = realm.admin().clients().create(visibleClient)) {
            visibleClient.setId(ApiUtil.getCreatedId(response));
        }

        ClientRepresentation secretClient = new ClientRepresentation();
        secretClient.setClientId("secret-client");
        try (Response response = realm.admin().clients().create(secretClient)) {
            secretClient.setId(ApiUtil.getCreatedId(response));
        }

        RoleRepresentation visibleChild = new RoleRepresentation();
        visibleChild.setName("VISIBLE_CHILD");
        realm.admin().clients().get(visibleClient.getId()).roles().create(visibleChild);
        visibleChild = realm.admin().clients().get(visibleClient.getId()).roles().get("VISIBLE_CHILD").toRepresentation();

        RoleRepresentation secretChild = new RoleRepresentation();
        secretChild.setName("SECRET_CHILD");
        realm.admin().clients().get(secretClient.getId()).roles().create(secretChild);
        secretChild = realm.admin().clients().get(secretClient.getId()).roles().get("SECRET_CHILD").toRepresentation();

        RoleRepresentation visibleParent = new RoleRepresentation();
        visibleParent.setName("VISIBLE_PARENT");
        realm.admin().clients().get(visibleClient.getId()).roles().create(visibleParent);
        visibleParent = realm.admin().clients().get(visibleClient.getId()).roles().get("VISIBLE_PARENT").toRepresentation();
        realm.admin().clients().get(visibleClient.getId()).roles().get("VISIBLE_PARENT").addComposites(List.of(visibleChild, secretChild));

        RoleRepresentation realmParent = new RoleRepresentation();
        realmParent.setName("REALM_PARENT");
        realm.admin().roles().create(realmParent);
        realmParent = realm.admin().roles().get("REALM_PARENT").toRepresentation();
        realm.cleanup().add(r -> r.roles().get("REALM_PARENT").remove());
        realm.admin().roles().get("REALM_PARENT").addComposites(List.of(visibleChild, secretChild));

        String realmMgmtId = realm.admin().clients().findByClientId("realm-management").get(0).getId();
        RoleRepresentation manageRealmRole = realm.admin().clients().get(realmMgmtId).roles().get("manage-realm").toRepresentation();
        realm.admin().users().get(myadmin.getId()).roles().clientLevel(realmMgmtId).add(List.of(manageRealmRole));
        realmAdminClient.tokenManager().grantToken();

        UserRepresentation targetUser = createUser("targetUser");
        realm.admin().users().get(targetUser.getId()).roles().clientLevel(visibleClient.getId()).add(List.of(visibleChild));
        realm.admin().users().get(targetUser.getId()).roles().clientLevel(secretClient.getId()).add(List.of(secretChild));

        UserPolicyRepresentation policy = createUserPolicy(realm, adminPermissionsClient, "Only My Admin User Policy", myadmin.getId());
        createPermission(adminPermissionsClient, visibleClient.getId(), AdminPermissionsSchema.CLIENTS_RESOURCE_TYPE, Set.of(VIEW), policy);
        createPermission(adminPermissionsClient, targetUser.getId(), AdminPermissionsSchema.USERS_RESOURCE_TYPE, Set.of(VIEW), policy);

        Set<String> roleNames;

        // GET /clients/{clientUuid}/roles/{roleName}/composites
        roleNames = realmAdminClient.realm(realm.getName())
                .clients().get(visibleClient.getId()).roles().get("VISIBLE_PARENT").getRoleComposites()
                .stream().map(RoleRepresentation::getName).collect(Collectors.toSet());
        assertThat(roleNames, hasItem("VISIBLE_CHILD"));
        assertThat(roleNames, not(hasItem("SECRET_CHILD")));

        // GET /clients/{clientUuid}/roles/{roleName}/composites/clients/{hiddenClientUuid}
        assertThat(realmAdminClient.realm(realm.getName())
                .clients().get(visibleClient.getId()).roles().get("VISIBLE_PARENT")
                .getClientRoleComposites(secretClient.getId()), empty());

        // GET /roles-by-id/{roleId}/composites
        roleNames = realmAdminClient.realm(realm.getName())
                .rolesById().getRoleComposites(visibleParent.getId())
                .stream().map(RoleRepresentation::getName).collect(Collectors.toSet());
        assertThat(roleNames, hasItem("VISIBLE_CHILD"));
        assertThat(roleNames, not(hasItem("SECRET_CHILD")));

        // GET /roles-by-id/{roleId}/composites/clients/{hiddenClientUuid}
        assertThat(realmAdminClient.realm(realm.getName())
                .rolesById().getClientRoleComposites(visibleParent.getId(), secretClient.getId()), empty());

        // GET /roles/{roleName}/composites
        roleNames = realmAdminClient.realm(realm.getName())
                .roles().get("REALM_PARENT").getRoleComposites()
                .stream().map(RoleRepresentation::getName).collect(Collectors.toSet());
        assertThat(roleNames, hasItem("VISIBLE_CHILD"));
        assertThat(roleNames, not(hasItem("SECRET_CHILD")));

        // GET /users/{userId}/role-mappings — directly mapped roles from hidden clients should be filtered
        MappingsRepresentation mappings = realmAdminClient.realm(realm.getName())
                .users().get(targetUser.getId()).roles().getAll();
        Map<String, ClientMappingsRepresentation> clientMappings = mappings.getClientMappings();
        assertThat("visible-client mapping must be present", clientMappings, not(equalTo(null)));
        Set<String> allClientRoleNames = clientMappings.values().stream()
                .flatMap(m -> m.getMappings().stream())
                .map(RoleRepresentation::getName)
                .collect(Collectors.toSet());
        assertThat(allClientRoleNames, hasItem("VISIBLE_CHILD"));
        assertThat(allClientRoleNames, not(hasItem("SECRET_CHILD")));
        assertThat("secret-client should not appear in client mappings",
                clientMappings.containsKey("secret-client"), equalTo(false));
    }

    private RoleRepresentation createRealmRole(String name) {
        RoleRepresentation role = new RoleRepresentation();
        role.setName(name);
        realm.admin().roles().create(role);
        realm.cleanup().add(r -> r.roles().get(name).remove());
        return realm.admin().roles().get(name).toRepresentation();
    }

    private ClientRepresentation createClient(String clientId) {
        ClientRepresentation client = new ClientRepresentation();
        client.setClientId(clientId);
        try (Response response = realm.admin().clients().create(client)) {
            client.setId(ApiUtil.getCreatedId(response));
        }
        return client;
    }

    private RoleRepresentation createClientRole(ClientRepresentation client, String name) {
        RoleRepresentation role = new RoleRepresentation();
        role.setName(name);
        realm.admin().clients().get(client.getId()).roles().create(role);
        return realm.admin().clients().get(client.getId()).roles().get(name).toRepresentation();
    }

    private String getUiExtEndpoint(String subPath) {
        try (Client httpClient = Keycloak.getClientProvider().newRestEasyClient(null, null, true)) {
            return getUiExtEndpoint(httpClient, keycloakUrls.getBaseUrl().toString(), realm.getName(), subPath,
                    new BearerAuthFilter(realmAdminClient.tokenManager()));
        }
    }

    private String getUiExtEndpoint(Client httpClient, String baseUrl, String realmName, String subPath, BearerAuthFilter bearerAuth) {
        WebTarget target = httpClient.target(baseUrl)
                .path("admin").path("realms").path(realmName)
                .path("ui-ext").path(subPath)
                .register(bearerAuth);
        Response response = target.request(MediaType.APPLICATION_JSON).get();
        assertThat(response.getStatus(), equalTo(Response.Status.OK.getStatusCode()));
        return response.readEntity(String.class);
    }
}
