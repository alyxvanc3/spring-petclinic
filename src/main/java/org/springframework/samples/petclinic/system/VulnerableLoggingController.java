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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
class VulnerableLoggingController {

	private static final Logger logger = LoggerFactory.getLogger(VulnerableLoggingController.class);

	@PostMapping("/support/vulnerable-login-debug")
	LoggingDebugResponse logLoginTroubleshootingData(@RequestBody LoginTroubleshootingRequest request) {
		// WARNING: Intentionally vulnerable logging examples for educational security
		// testing and static analysis experiments. Do not copy this pattern into
		// production code.
		//
		// User-controlled input and sensitive fields are written directly to
		// application logs without redaction, encoding, or log-injection defenses.
		logger.info("Login debug request from user=" + request.username() + ", message=" + request.diagnosticMessage());
		logger.warn("Failed login details: email={}, password={}, mfaCode={}", request.email(), request.password(),
				request.mfaCode());
		logger.error("Support escalation for ssn={}, sessionToken={}, apiKey={}", request.ssn(), request.sessionToken(),
				request.apiKey());

		return new LoggingDebugResponse("logged", request.username());
	}

	record LoginTroubleshootingRequest(String username, String email, String password, String mfaCode, String ssn,
			String sessionToken, String apiKey, String diagnosticMessage) {
	}

	record LoggingDebugResponse(String status, String username) {
	}

}
