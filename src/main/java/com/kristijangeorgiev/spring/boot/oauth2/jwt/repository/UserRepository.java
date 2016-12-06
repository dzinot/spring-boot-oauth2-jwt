package com.kristijangeorgiev.spring.boot.oauth2.jwt.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import com.kristijangeorgiev.spring.boot.oauth2.jwt.model.entity.User;

/**
 * 
 * @author Kristijan Georgiev
 * 
 *         UserRepository with custom methods for finding an active User by
 *         username or email
 *
 */

@Repository
@Transactional
public interface UserRepository extends JpaRepository<User, Long> {

	@Query("SELECT u FROM User u WHERE (u.deletedOn > CURRENT_TIMESTAMP OR u.deletedOn IS NULL) AND u.username = :username")
	User findActiveByUsername(@Param("username") String username);

	@Query("SELECT u FROM User u WHERE (u.deletedOn > CURRENT_TIMESTAMP OR u.deletedOn IS NULL) AND u.email = :email")
	User findActiveByEmail(@Param("email") String email);

}
