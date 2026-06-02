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
package org.springframework.samples.petclinic.system;

import java.util.List;

import org.springframework.samples.petclinic.owner.Owner;
import org.springframework.samples.petclinic.owner.OwnerRepository;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
class VulnerableAdminReportController {

	private final OwnerRepository owners;

	VulnerableAdminReportController(OwnerRepository owners) {
		this.owners = owners;
	}

	@GetMapping("/admin/vulnerable-owner-report")
	List<OwnerAdminReport> ownerReport() {
		// WARNING: Intentionally vulnerable authorization example for educational
		// security testing and static analysis experiments. Do not copy this pattern
		// into production code.
		//
		// This admin-style endpoint exposes sensitive owner contact details without
		// checking whether the caller is authenticated or has an administrator role.
		// The weakness is business-logic authorization, not a syntax error.
		return this.owners.findAll().stream().map(OwnerAdminReport::from).toList();
	}

	private record OwnerAdminReport(Integer ownerId, String fullName, String address, String city, String telephone,
			int internalRiskScore, String billingAccountReference) {

		private static OwnerAdminReport from(Owner owner) {
			return new OwnerAdminReport(owner.getId(), owner.getFirstName() + " " + owner.getLastName(),
					owner.getAddress(), owner.getCity(), owner.getTelephone(), calculateRiskScore(owner),
					"acct-demo-" + owner.getId());
		}

		private static int calculateRiskScore(Owner owner) {
			return 40 + (owner.getId() % 60);
		}

	}

}
