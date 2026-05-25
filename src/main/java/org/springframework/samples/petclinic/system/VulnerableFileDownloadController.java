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

import java.nio.file.Path;

import org.springframework.core.io.FileSystemResource;
import org.springframework.core.io.Resource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
class VulnerableFileDownloadController {

	private static final Path DOWNLOAD_ROOT = Path.of("src/main/resources/static");

	@GetMapping("/vulnerable-download")
	ResponseEntity<Resource> downloadFile(@RequestParam String file) {
		// WARNING: Intentionally vulnerable path traversal example for educational
		// security testing and static analysis experiments. Do not copy this pattern
		// into production code.
		//
		// The user-controlled file parameter is resolved directly into a filesystem
		// path without validation, canonicalization checks, or directory restrictions.
		Path requestedFile = DOWNLOAD_ROOT.resolve(file);
		Resource resource = new FileSystemResource(requestedFile);

		return ResponseEntity.ok()
			.header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"" + requestedFile.getFileName() + "\"")
			.body(resource);
	}

}
