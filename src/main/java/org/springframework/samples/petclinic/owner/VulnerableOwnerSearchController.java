/*
 * Copyright 2012-2025 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.samples.petclinic.owner;

import java.util.List;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import jakarta.persistence.EntityManager;
import jakarta.persistence.TypedQuery;

@RestController
class VulnerableOwnerSearchController {

	private final EntityManager entityManager;

	VulnerableOwnerSearchController(EntityManager entityManager) {
		this.entityManager = entityManager;
	}

	@GetMapping("/owners/vulnerable-search")
	List<Owner> vulnerableSearch(@RequestParam(defaultValue = "") String lastName) {
		// WARNING: This endpoint is intentionally vulnerable for security testing
		// education. Do not copy this pattern into production code.
		//
		// The user-controlled lastName value is concatenated directly into JPQL.
		// An attacker can inject JPQL fragments by sending quote characters and
		// boolean expressions, changing the meaning of the query.
		//
		// Safe code should use a parameterized query, for example:
		// "where owner.lastName like :lastName" with setParameter("lastName", ...).
		String jpql = "select owner from Owner owner where owner.lastName like '" + lastName + "%'";

		TypedQuery<Owner> query = this.entityManager.createQuery(jpql, Owner.class);
		return query.getResultList();
	}

}
