extern crate serde;
#[macro_use]
extern crate serde_derive;
extern crate failure;
#[macro_use]
extern crate failure_derive;

pub mod model;

use crate::model::Owned;
use std::collections::HashMap;

#[derive(Fail, Debug)]
pub enum AuthError {
    #[fail(display = "UnAuthenticatedError")]
    UnAuthenticatedError {},
    #[fail(display = "UnAuthorizedError [{}]", message)]
    UnAuthorizedError { message: String },
}

pub struct AuthService {
    roles_provider: Box<RolesProvider>,
}

pub fn new(roles_provider: Box<RolesProvider>) -> AuthService {
    AuthService { roles_provider }
}

impl AuthService {
    pub fn auth(&self, auth: model::Auth) -> AuthContext {
        AuthContext::new(auth, &*self.roles_provider)
    }
}

pub struct AuthContext<'a> {
    pub auth: model::Auth,
    permissions: Vec<&'a String>,
}

impl<'a> AuthContext<'a> {
    pub fn new(auth: model::Auth, roles_provider: &RolesProvider) -> AuthContext {
        let mut permissions = vec![];

        for role in roles_provider.get_by_name(&auth.roles) {
            for permission in &role.permissions {
                permissions.push(permission)
            }
        }

        AuthContext { auth, permissions }
    }

    pub fn is_authenticated(&self) -> Result<&AuthContext, AuthError> {
        if self.auth.username.is_empty() {
            return Err(AuthError::UnAuthenticatedError {});
        };
        Ok(&self)
    }

    pub fn has_role(&self, role: &str) -> Result<&AuthContext, AuthError> {
        self.is_authenticated()?;
        if !self.has_role_bool(&role) {
            return Err(AuthError::UnAuthorizedError {
                message: format!(
                    "User [{}] does not have the required role [{}]",
                    self.auth.id, role
                ),
            });
        };
        Ok(&self)
    }

    pub fn has_any_role(&self, roles: &[&str]) -> Result<&AuthContext, AuthError> {
        self.is_authenticated()?;
        for role in roles {
            if self.has_role_bool(*role) {
                return Ok(&self);
            };
        }
        Err(AuthError::UnAuthorizedError {
            message: format!("User [{}] does not have the required role", self.auth.id),
        })
    }

    pub fn has_all_roles(&self, roles: &[&str]) -> Result<&AuthContext, AuthError> {
        self.is_authenticated()?;
        for role in roles {
            if !self.has_role_bool(*role) {
                return Err(AuthError::UnAuthorizedError {
                    message: format!(
                        "User [{}] does not have the required role [{}]",
                        self.auth.id, role
                    ),
                });
            };
        }
        Ok(&self)
    }

    pub fn has_permission(&self, permission: &str) -> Result<&AuthContext, AuthError> {
        self.is_authenticated()?;
        if !self.has_permission_bool(&permission) {
            return Err(AuthError::UnAuthorizedError {
                message: format!(
                    "User [{}] does not have the required permission [{}]",
                    self.auth.id, permission
                ),
            });
        };
        Ok(&self)
    }

    pub fn has_any_permission(&self, permissions: &[&str]) -> Result<&AuthContext, AuthError> {
        self.is_authenticated()?;
        for permission in permissions {
            if self.has_permission_bool(*permission) {
                return Ok(&self);
            };
        }
        Err(AuthError::UnAuthorizedError {
            message: format!(
                "User [{}] does not have the required permission",
                self.auth.id
            ),
        })
    }

    pub fn has_all_permissions(&self, permissions: &[&str]) -> Result<&AuthContext, AuthError> {
        self.is_authenticated()?;
        for permission in permissions {
            if !self.has_permission_bool(*permission) {
                return Err(AuthError::UnAuthorizedError {
                    message: format!(
                        "User [{}] does not have the required permission [{}]",
                        self.auth.id, permission
                    ),
                });
            };
        }
        Ok(&self)
    }

    pub fn is_owner<T: Owned>(&self, obj: &T) -> Result<&AuthContext, AuthError> {
        if self.auth.id == obj.get_owner_id() {
            Ok(&self)
        } else {
            Err(AuthError::UnAuthorizedError {
                message: format!(
                    "User [{}] is not the owner. User id [{}], owner id: [{}]",
                    self.auth.id,
                    self.auth.id,
                    obj.get_owner_id()
                ),
            })
        }
    }

    pub fn is_owner_or_has_role<T: Owned>(
        &self,
        obj: &T,
        role: &str,
    ) -> Result<&AuthContext, AuthError> {
        if (self.auth.id == obj.get_owner_id()) || self.has_role_bool(role) {
            Ok(&self)
        } else {
            Err(AuthError::UnAuthorizedError { message: format!("User [{}] is not the owner and does not have role [{}]. User id [{}], owner id: [{}]", self.auth.id, role, self.auth.id, obj.get_owner_id() ) })
        }
    }

    pub fn is_owner_or_has_permission<T: Owned>(
        &self,
        obj: &T,
        permission: &str,
    ) -> Result<&AuthContext, AuthError> {
        if (self.auth.id == obj.get_owner_id()) || self.has_permission_bool(permission) {
            Ok(&self)
        } else {
            Err(AuthError::UnAuthorizedError { message: format!("User [{}] is not the owner and does not have permission [{}]. User id [{}], owner id: [{}]", self.auth.id, permission, self.auth.id, obj.get_owner_id() ) })
        }
    }

    fn has_role_bool(&self, role: &str) -> bool {
        self.auth.roles.contains(&role.to_string())
    }

    fn has_permission_bool(&self, permission: &str) -> bool {
        self.permissions.contains(&&permission.to_string())
    }
}

pub trait RolesProvider: Send + Sync {
    fn get_all(&self) -> &Vec<model::Role>;

    fn get_by_name(&self, names: &[String]) -> Vec<&model::Role>;
}

pub struct InMemoryRolesProvider {
    all_roles: Vec<model::Role>,
    roles_by_name: HashMap<String, model::Role>,
}

impl InMemoryRolesProvider {
    pub fn new(all_roles: Vec<model::Role>) -> InMemoryRolesProvider {
        let mut provider = InMemoryRolesProvider {
            all_roles,
            roles_by_name: HashMap::new(),
        };

        for role in &provider.all_roles {
            provider
                .roles_by_name
                .insert(role.name.clone(), role.clone());
        }

        provider
    }
}

impl RolesProvider for InMemoryRolesProvider {
    fn get_all(&self) -> &Vec<model::Role> {
        &self.all_roles
    }

    fn get_by_name(&self, names: &[String]) -> Vec<&model::Role> {
        let mut result = vec![];
        for name in names {
            let roles = self.roles_by_name.get(name);
            if let Some(t) = roles { result.push(t) }
        }
        result
    }
}

#[cfg(test)]
mod test_role_provider {
    use super::model::Role;
    use super::RolesProvider;

    #[test]
    fn should_return_all_roles() {
        let roles = vec![
            Role {
                name: "RoleOne".to_string(),
                permissions: vec![],
            },
            Role {
                name: "RoleTwo".to_string(),
                permissions: vec![],
            },
        ];
        let provider = super::InMemoryRolesProvider::new(roles.clone());
        let get_all = provider.get_all();
        assert!(!get_all.is_empty());
        assert_eq!(roles.len(), get_all.len());
        assert_eq!(&roles[0].name, &get_all[0].name);
        assert_eq!(&roles[1].name, &get_all[1].name);
    }

    #[test]
    fn should_return_empty_if_no_matching_names() {
        let roles = vec![
            Role {
                name: "RoleOne".to_string(),
                permissions: vec![],
            },
            Role {
                name: "RoleTwo".to_string(),
                permissions: vec![],
            },
        ];
        let provider = super::InMemoryRolesProvider::new(roles.clone());
        let get_by_name = provider.get_by_name(&vec![]);
        assert!(get_by_name.is_empty());
    }

    #[test]
    fn should_return_role_by_name() {
        let roles = vec![
            Role {
                name: "RoleOne".to_string(),
                permissions: vec![],
            },
            Role {
                name: "RoleTwo".to_string(),
                permissions: vec![],
            },
        ];
        let provider = super::InMemoryRolesProvider::new(roles.clone());
        let get_by_name = provider.get_by_name(&vec!["RoleOne".to_string()]);
        assert!(!get_by_name.is_empty());
        assert_eq!(1, get_by_name.len());
        assert_eq!("RoleOne", &get_by_name[0].name);
    }
}

#[cfg(test)]
mod test_auth_context {

    use super::model::{Auth, Owned, Role};

    #[test]
    fn should_be_authenticated() {
        let provider = Box::new(super::InMemoryRolesProvider::new(vec![]));
        let auth_service = super::AuthService {
            roles_provider: provider,
        };
        let user = Auth {
            id: 0,
            username: "name".to_string(),
            roles: vec![],
        };
        let auth_context = auth_service.auth(user);
        assert!(auth_context.is_authenticated().is_ok());
    }

    #[test]
    fn should_be_not_authenticated() {
        let provider = Box::new(super::InMemoryRolesProvider::new(vec![]));
        let auth_service = super::AuthService {
            roles_provider: provider,
        };
        let user = Auth {
            id: 0,
            username: "".to_string(),
            roles: vec![],
        };
        let auth_context = auth_service.auth(user);
        assert!(auth_context.is_authenticated().is_err());
    }

    #[test]
    fn should_be_not_authenticated_even_if_has_role() {
        let provider = Box::new(super::InMemoryRolesProvider::new(vec![]));
        let auth_service = super::AuthService {
            roles_provider: provider,
        };
        let user = Auth {
            id: 0,
            username: "".to_string(),
            roles: vec!["ADMIN".to_string()],
        };
        let auth_context = auth_service.auth(user);
        assert!(auth_context.has_role("ADMIN").is_err());
    }

    #[test]
    fn should_have_role() {
        let provider = Box::new(super::InMemoryRolesProvider::new(vec![]));
        let auth_service = super::AuthService {
            roles_provider: provider,
        };
        let user = Auth {
            id: 0,
            username: "name".to_string(),
            roles: vec!["ADMIN".to_string()],
        };
        let auth_context = auth_service.auth(user);
        assert!(auth_context.has_role("ADMIN").is_ok());
    }

    #[test]
    fn should_have_role_2() {
        let provider = Box::new(super::InMemoryRolesProvider::new(vec![]));
        let auth_service = super::AuthService {
            roles_provider: provider,
        };
        let user = Auth {
            id: 0,
            username: "name".to_string(),
            roles: vec!["ADMIN".to_string(), "USER".to_string()],
        };
        let auth_context = auth_service.auth(user);
        assert!(auth_context.has_role("USER").is_ok());
    }

    #[test]
    fn should_not_have_role() {
        let provider = Box::new(super::InMemoryRolesProvider::new(vec![]));
        let auth_service = super::AuthService {
            roles_provider: provider,
        };
        let user = Auth {
            id: 0,
            username: "name".to_string(),
            roles: vec!["ADMIN".to_string()],
        };
        let auth_context = auth_service.auth(user);
        assert!(auth_context.has_role("USER").is_err());
    }

    #[test]
    fn should_have_any_role() {
        let provider = Box::new(super::InMemoryRolesProvider::new(vec![]));
        let auth_service = super::AuthService {
            roles_provider: provider,
        };
        let user = Auth {
            id: 0,
            username: "name".to_string(),
            roles: vec!["ADMIN".to_string(), "USER".to_string()],
        };
        let auth_context = auth_service.auth(user);
        assert!(auth_context.has_any_role(&["USER", "FRIEND"]).is_ok());
    }

    #[test]
    fn should_not_have_any_role() {
        let provider = Box::new(super::InMemoryRolesProvider::new(vec![]));
        let auth_service = super::AuthService {
            roles_provider: provider,
        };
        let user = Auth {
            id: 0,
            username: "name".to_string(),
            roles: vec!["ADMIN".to_string(), "OWNER".to_string()],
        };
        let auth_context = auth_service.auth(user);
        assert!(auth_context.has_any_role(&["USER", "FRIEND"]).is_err());
    }

    #[test]
    fn should_have_all_roles() {
        let provider = Box::new(super::InMemoryRolesProvider::new(vec![]));
        let auth_service = super::AuthService {
            roles_provider: provider,
        };
        let user = Auth {
            id: 0,
            username: "name".to_string(),
            roles: vec![
                "ADMIN".to_string(),
                "USER".to_string(),
                "FRIEND".to_string(),
            ],
        };
        let auth_context = auth_service.auth(user);
        assert!(auth_context.has_all_roles(&["USER", "FRIEND"]).is_ok());
    }

    #[test]
    fn should_not_have_all_roles() {
        let provider = Box::new(super::InMemoryRolesProvider::new(vec![]));
        let auth_service = super::AuthService {
            roles_provider: provider,
        };
        let user = Auth {
            id: 0,
            username: "name".to_string(),
            roles: vec!["ADMIN".to_string(), "USER".to_string()],
        };
        let auth_context = auth_service.auth(user);
        assert!(auth_context.has_all_roles(&["USER", "FRIEND"]).is_err());
    }

    #[test]
    fn should_be_not_authenticated_even_if_has_permission() {
        let roles = vec![Role {
            name: "ADMIN".to_string(),
            permissions: vec!["delete".to_string()],
        }];
        let provider = Box::new(super::InMemoryRolesProvider::new(roles.clone()));
        let auth_service = super::AuthService {
            roles_provider: provider,
        };
        let user = Auth {
            id: 0,
            username: "".to_string(),
            roles: vec!["ADMIN".to_string()],
        };
        let auth_context = auth_service.auth(user);
        assert!(auth_context.has_permission("delete").is_err());
    }

    #[test]
    fn should_have_permission() {
        let roles = vec![
            Role {
                name: "ADMIN".to_string(),
                permissions: vec!["delete".to_string()],
            },
            Role {
                name: "OWNER".to_string(),
                permissions: vec!["create".to_string()],
            },
        ];
        let provider = Box::new(super::InMemoryRolesProvider::new(roles.clone()));
        let auth_service = super::AuthService {
            roles_provider: provider,
        };
        let user = Auth {
            id: 0,
            username: "name".to_string(),
            roles: vec!["ADMIN".to_string()],
        };
        let auth_context = auth_service.auth(user);
        assert!(auth_context.has_permission("delete").is_ok());
    }

    #[test]
    fn should_have_permission_2() {
        let roles = vec![
            Role {
                name: "ADMIN".to_string(),
                permissions: vec!["delete".to_string()],
            },
            Role {
                name: "OWNER".to_string(),
                permissions: vec!["delete".to_string()],
            },
        ];
        let provider = Box::new(super::InMemoryRolesProvider::new(roles.clone()));
        let auth_service = super::AuthService {
            roles_provider: provider,
        };
        let user = Auth {
            id: 0,
            username: "name".to_string(),
            roles: vec!["ADMIN".to_string(), "OWNER".to_string()],
        };
        let auth_context = auth_service.auth(user);
        assert!(auth_context.has_permission("delete").is_ok());
    }

    #[test]
    fn should_not_have_permission() {
        let roles = vec![
            Role {
                name: "ADMIN".to_string(),
                permissions: vec!["delete".to_string()],
            },
            Role {
                name: "OWNER".to_string(),
                permissions: vec!["delete".to_string()],
            },
        ];
        let provider = Box::new(super::InMemoryRolesProvider::new(roles.clone()));
        let auth_service = super::AuthService {
            roles_provider: provider,
        };
        let user = Auth {
            id: 0,
            username: "name".to_string(),
            roles: vec!["USER".to_string()],
        };
        let auth_context = auth_service.auth(user);
        assert!(auth_context.has_permission("delete").is_err());
    }

    #[test]
    fn should_have_any_permission() {
        let roles = vec![
            Role {
                name: "ADMIN".to_string(),
                permissions: vec!["superDelete".to_string()],
            },
            Role {
                name: "OWNER".to_string(),
                permissions: vec!["delete".to_string()],
            },
        ];
        let provider = Box::new(super::InMemoryRolesProvider::new(roles.clone()));
        let auth_service = super::AuthService {
            roles_provider: provider,
        };
        let user = Auth {
            id: 0,
            username: "name".to_string(),
            roles: vec!["USER".to_string(), "ADMIN".to_string()],
        };
        let auth_context = auth_service.auth(user);
        assert!(
            auth_context
                .has_any_permission(&["delete", "superDelete"])
                .is_ok()
        );
    }

    #[test]
    fn should_not_have_any_permission() {
        let roles = vec![
            Role {
                name: "ADMIN".to_string(),
                permissions: vec!["delete".to_string(), "superDelete".to_string()],
            },
            Role {
                name: "OWNER".to_string(),
                permissions: vec!["delete".to_string()],
            },
        ];
        let provider = Box::new(super::InMemoryRolesProvider::new(roles.clone()));
        let auth_service = super::AuthService {
            roles_provider: provider,
        };
        let user = Auth {
            id: 0,
            username: "name".to_string(),
            roles: vec!["USER".to_string()],
        };
        let auth_context = auth_service.auth(user);
        assert!(
            auth_context
                .has_any_permission(&["delete", "superAdmin"])
                .is_err()
        );
    }

    #[test]
    fn should_have_all_permissions() {
        let roles = vec![
            Role {
                name: "ADMIN".to_string(),
                permissions: vec!["superDelete".to_string()],
            },
            Role {
                name: "OWNER".to_string(),
                permissions: vec!["delete".to_string()],
            },
            Role {
                name: "USER".to_string(),
                permissions: vec!["delete".to_string()],
            },
        ];
        let provider = Box::new(super::InMemoryRolesProvider::new(roles.clone()));
        let auth_service = super::AuthService {
            roles_provider: provider,
        };
        let user = Auth {
            id: 0,
            username: "name".to_string(),
            roles: vec!["USER".to_string(), "ADMIN".to_string()],
        };
        let auth_context = auth_service.auth(user);
        assert!(
            auth_context
                .has_all_permissions(&["delete", "superDelete"])
                .is_ok()
        );
    }

    #[test]
    fn should_not_have_all_permissions() {
        let roles = vec![
            Role {
                name: "ADMIN".to_string(),
                permissions: vec!["superDelete".to_string()],
            },
            Role {
                name: "OWNER".to_string(),
                permissions: vec!["delete".to_string()],
            },
        ];
        let provider = Box::new(super::InMemoryRolesProvider::new(roles.clone()));
        let auth_service = super::AuthService {
            roles_provider: provider,
        };
        let user = Auth {
            id: 0,
            username: "name".to_string(),
            roles: vec!["USER".to_string(), "ADMIN".to_string()],
        };
        let auth_context = auth_service.auth(user);
        assert!(
            auth_context
                .has_all_permissions(&["delete", "superDelete"])
                .is_err()
        );
    }

    #[test]
    fn should_be_the_owner() {
        let roles = vec![];
        let provider = Box::new(super::InMemoryRolesProvider::new(roles.clone()));
        let auth_service = super::AuthService {
            roles_provider: provider,
        };
        let user = Auth {
            id: 0,
            username: "name".to_string(),
            roles: vec!["USER".to_string(), "ADMIN".to_string()],
        };
        let auth_context = auth_service.auth(user);
        assert!(auth_context.is_owner(&Ownable { owner_id: 0 }).is_ok());
    }

    #[test]
    fn should_not_be_the_owner() {
        let roles = vec![];
        let provider = Box::new(super::InMemoryRolesProvider::new(roles.clone()));
        let auth_service = super::AuthService {
            roles_provider: provider,
        };
        let user = Auth {
            id: 0,
            username: "name".to_string(),
            roles: vec!["USER".to_string(), "ADMIN".to_string()],
        };
        let auth_context = auth_service.auth(user);
        assert!(auth_context.is_owner(&Ownable { owner_id: 1 }).is_err());
    }

    #[test]
    fn should_be_allowed_if_not_the_owner_but_has_role() {
        let roles = vec![Role {
            name: "ROLE_1".to_string(),
            permissions: vec!["access_1".to_string()],
        }];
        let provider = Box::new(super::InMemoryRolesProvider::new(roles.clone()));
        let auth_service = super::AuthService {
            roles_provider: provider,
        };
        let user = Auth {
            id: 0,
            username: "name".to_string(),
            roles: vec!["ROLE_1".to_string()],
        };
        let auth_context = auth_service.auth(user);
        assert!(
            auth_context
                .is_owner_or_has_role(&Ownable { owner_id: 1 }, "ROLE_1")
                .is_ok()
        );
    }

    #[test]
    fn should_be_allowed_if_the_owner_but_not_has_role() {
        let roles = vec![Role {
            name: "ROLE_1".to_string(),
            permissions: vec!["access_1".to_string()],
        }];
        let provider = Box::new(super::InMemoryRolesProvider::new(roles.clone()));
        let auth_service = super::AuthService {
            roles_provider: provider,
        };
        let user = Auth {
            id: 0,
            username: "name".to_string(),
            roles: vec!["ROLE_1".to_string()],
        };
        let auth_context = auth_service.auth(user);
        assert!(
            auth_context
                .is_owner_or_has_role(&Ownable { owner_id: 0 }, "ROLE_2")
                .is_ok()
        );
    }

    #[test]
    fn should_not_be_allowed_if_not_the_owner_and_not_has_role() {
        let roles = vec![Role {
            name: "ROLE_1".to_string(),
            permissions: vec!["access_1".to_string()],
        }];
        let provider = Box::new(super::InMemoryRolesProvider::new(roles.clone()));
        let auth_service = super::AuthService {
            roles_provider: provider,
        };
        let user = Auth {
            id: 0,
            username: "name".to_string(),
            roles: vec!["ROLE_1".to_string()],
        };
        let auth_context = auth_service.auth(user);
        assert!(
            auth_context
                .is_owner_or_has_role(&Ownable { owner_id: 1 }, "ROLE_2")
                .is_err()
        );
    }

    #[test]
    fn should_be_allowed_if_not_the_owner_but_has_permission() {
        let roles = vec![Role {
            name: "ROLE_1".to_string(),
            permissions: vec!["access_1".to_string()],
        }];
        let provider = Box::new(super::InMemoryRolesProvider::new(roles.clone()));
        let auth_service = super::AuthService {
            roles_provider: provider,
        };
        let user = Auth {
            id: 0,
            username: "name".to_string(),
            roles: vec!["ROLE_1".to_string()],
        };
        let auth_context = auth_service.auth(user);
        assert!(
            auth_context
                .is_owner_or_has_permission(&Ownable { owner_id: 1 }, "access_1")
                .is_ok()
        );
    }

    #[test]
    fn should_be_allowed_if_the_owner_but_not_has_permission() {
        let roles = vec![Role {
            name: "ROLE_1".to_string(),
            permissions: vec!["access_1".to_string()],
        }];
        let provider = Box::new(super::InMemoryRolesProvider::new(roles.clone()));
        let auth_service = super::AuthService {
            roles_provider: provider,
        };
        let user = Auth {
            id: 0,
            username: "name".to_string(),
            roles: vec!["ROLE_1".to_string()],
        };
        let auth_context = auth_service.auth(user);
        assert!(
            auth_context
                .is_owner_or_has_permission(&Ownable { owner_id: 0 }, "access_2")
                .is_ok()
        );
    }

    #[test]
    fn should_not_be_allowed_if_not_the_owner_and_not_has_permission() {
        let roles = vec![Role {
            name: "ROLE_1".to_string(),
            permissions: vec!["access_1".to_string()],
        }];
        let provider = Box::new(super::InMemoryRolesProvider::new(roles.clone()));
        let auth_service = super::AuthService {
            roles_provider: provider,
        };
        let user = Auth {
            id: 0,
            username: "name".to_string(),
            roles: vec!["ROLE_1".to_string()],
        };
        let auth_context = auth_service.auth(user);
        assert!(
            auth_context
                .is_owner_or_has_permission(&Ownable { owner_id: 1 }, "access_2")
                .is_err()
        );
    }

    struct Ownable {
        owner_id: i64,
    }

    impl Owned for Ownable {
        fn get_owner_id(&self) -> i64 {
            return self.owner_id;
        }
    }
}
