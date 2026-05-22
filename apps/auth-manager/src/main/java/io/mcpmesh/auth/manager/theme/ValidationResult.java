package io.mcpmesh.auth.manager.theme;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Result of running a theme zip through {@link ThemeValidator}.
 *
 * <p>{@code valid} is true iff {@code errors} is empty. When invalid,
 * {@code extractedFiles} may still contain whatever the validator managed to
 * unpack before failing -- but callers should not persist those bytes.
 *
 * <p>{@code extractedFiles} maps the in-zip path (POSIX-style, no leading
 * slash, no {@code ..}) to its raw content bytes. The validator may have
 * sanitized some bytes in place (e.g. SVG); callers should always persist
 * the {@code extractedFiles} bytes, NOT the original zip bytes.
 */
public final class ValidationResult {

    public record Error(String code, String path, String message) {}

    private final List<Error> errors;
    private final Map<String, byte[]> extractedFiles;

    public ValidationResult(List<Error> errors, Map<String, byte[]> extractedFiles) {
        this.errors = errors == null ? List.of() : List.copyOf(errors);
        this.extractedFiles = extractedFiles == null
            ? Map.of()
            : Map.copyOf(extractedFiles);
    }

    public boolean isValid() {
        return errors.isEmpty();
    }

    public List<Error> errors() {
        return errors;
    }

    public Map<String, byte[]> extractedFiles() {
        return extractedFiles;
    }

    /** Builder used by {@link ThemeValidator}. */
    public static final class Builder {
        private final List<Error> errors = new ArrayList<>();
        private final Map<String, byte[]> files = new LinkedHashMap<>();

        public Builder error(String code, String path, String message) {
            errors.add(new Error(code, path, message));
            return this;
        }

        public Builder file(String path, byte[] content) {
            files.put(path, content);
            return this;
        }

        public boolean hasFile(String path) {
            return files.containsKey(path);
        }

        public byte[] file(String path) {
            return files.get(path);
        }

        public Map<String, byte[]> files() {
            return files;
        }

        public boolean hasErrors() {
            return !errors.isEmpty();
        }

        public ValidationResult build() {
            return new ValidationResult(errors, files);
        }
    }
}
