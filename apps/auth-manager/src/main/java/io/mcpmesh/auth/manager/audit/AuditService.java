package io.mcpmesh.auth.manager.audit;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.mcpmesh.auth.manager.domain.audit.ActorKind;
import io.mcpmesh.auth.manager.domain.audit.AuditEvent;
import io.mcpmesh.auth.manager.domain.audit.AuditResult;
import io.mcpmesh.auth.manager.persistence.AuditEventRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.Map;
import java.util.UUID;

/**
 * Writes audit_events rows. Single entry point used by every state-changing
 * service in the platform. The actor / actorKind plumbing currently always
 * receives ("system", SERVICE) -- replaced with the authenticated principal
 * when auth-lib v2 lands.
 */
@Service
@Transactional(propagation = Propagation.REQUIRES_NEW)
public class AuditService {

    private static final Logger log = LoggerFactory.getLogger(AuditService.class);

    private final AuditEventRepository repo;
    private final ObjectMapper objectMapper;

    public AuditService(AuditEventRepository repo) {
        this.repo = repo;
        this.objectMapper = new ObjectMapper();
    }

    public AuditEvent recordSuccess(
        String actor, ActorKind actorKind,
        UUID tenantId, String action,
        String targetKind, String targetId,
        Object requestPayload,
        Map<String, Object> details
    ) {
        return write(actor, actorKind, tenantId, action, targetKind, targetId,
            hashOf(requestPayload), AuditResult.SUCCESS, details);
    }

    public AuditEvent recordFailure(
        String actor, ActorKind actorKind,
        UUID tenantId, String action,
        String targetKind, String targetId,
        Object requestPayload,
        Throwable error,
        Map<String, Object> details
    ) {
        var enriched = new java.util.LinkedHashMap<String, Object>();
        if (details != null) enriched.putAll(details);
        enriched.put("error.class", error.getClass().getName());
        enriched.put("error.message", String.valueOf(error.getMessage()));
        return write(actor, actorKind, tenantId, action, targetKind, targetId,
            hashOf(requestPayload), AuditResult.FAILURE, enriched);
    }

    private AuditEvent write(
        String actor, ActorKind actorKind,
        UUID tenantId, String action,
        String targetKind, String targetId,
        String requestHash, AuditResult result,
        Map<String, Object> details
    ) {
        AuditEvent ev = new AuditEvent(
            actor, actorKind, tenantId, action, targetKind, targetId,
            requestHash, result, details);
        AuditEvent saved = repo.save(ev);
        log.info("Audit: action={} result={} tenant={} actor={} target={}",
                 action, result, tenantId, actor, targetId);
        return saved;
    }

    /** sha256 hex of a canonical JSON encoding of the payload, or null if payload is null. */
    private String hashOf(Object payload) {
        if (payload == null) return null;
        try {
            byte[] bytes = objectMapper.writeValueAsBytes(payload);
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            return HexFormat.of().formatHex(md.digest(bytes));
        } catch (JsonProcessingException | NoSuchAlgorithmException e) {
            log.warn("Failed to compute request_hash; recording audit without it", e);
            return null;
        }
    }
}
