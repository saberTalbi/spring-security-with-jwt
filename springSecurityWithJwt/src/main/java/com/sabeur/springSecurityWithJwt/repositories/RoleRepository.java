package com.sabeur.springSecurityWithJwt.repositories;

import java.util.Optional;

import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

import com.sabeur.springSecurityWithJwt.entities.Role;
import com.sabeur.springSecurityWithJwt.entities.RoleName;

@Repository
public interface RoleRepository extends CrudRepository<Role, Long> {
	Optional<Role> findByRoleName(RoleName roleName);
}
