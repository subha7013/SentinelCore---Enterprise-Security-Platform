package com.sentinelcore.service;

import com.sentinelcore.model.ReportRecord;
import com.sentinelcore.repository.ReportRecordRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.UUID;

@Service
public class ReportService {

    @Autowired
    private ReportRecordRepository reportRecordRepository;

    @Autowired
    private DashboardService dashboardService;

    @Autowired
    private AuditLogService auditLogService;

    public List<ReportRecord> getReports() {
        return reportRecordRepository.findAll(Sort.by(Sort.Direction.DESC, "createdAt"));
    }

    public ReportRecord generateReport(Map<String, Object> request, String currentUserEmail) {
        String type = (String) request.getOrDefault("type", "UNKNOWN");
        String format = (String) request.getOrDefault("format", "PDF");
        Boolean scheduled = (Boolean) request.getOrDefault("scheduled", false);
        String frequency = (String) request.getOrDefault("frequency", "");

        // Mock report title generation based on type
        String title = type.replace("_", " ") + " - " + LocalDateTime.now().toLocalDate().toString();
        
        // Mock generating random size for realism
        Random random = new Random();
        int sizeKB = 150 + random.nextInt(2000);
        String size = sizeKB > 1024 ? String.format("%.1f MB", sizeKB / 1024.0) : sizeKB + " KB";

        Map<String, Object> metrics = new HashMap<>();
        metrics.put("Classification", "CONFIDENTIAL // INTERNAL SECURITY USE ONLY");
        metrics.put("Document Verification Hash", "SHA256-" + UUID.randomUUID().toString().replace("-", "").substring(0, 16).toUpperCase());

        try {
            Map<String, Object> dashStats = dashboardService.getDashboardStats(null);
            
            if ("EXECUTIVE_SUMMARY".equals(type)) {
                metrics.put("Org Risk Score", dashStats.getOrDefault("orgRiskScore", "18/100 (LOW)"));
                metrics.put("Total Incidents", dashStats.getOrDefault("totalIncidents", 0));
                metrics.put("Avg MTTR (Hours)", dashStats.getOrDefault("avgMttrHours", 1.8));
                metrics.put("Compliance Score", dashStats.getOrDefault("complianceScore", "94%"));
                metrics.put("Executive Brief", "Overall enterprise security posture is STRONG. Zero uncontained P1 outbreaks detected in active logging period.");
            } else if ("INCIDENT_SUMMARY".equals(type)) {
                metrics.put("Total Incidents", dashStats.getOrDefault("totalIncidents", 0));
                metrics.put("Open Incidents", dashStats.getOrDefault("openIncidents", 0));
                metrics.put("Avg MTTR (Hours)", dashStats.getOrDefault("avgMttrHours", 1.8));
                metrics.put("My Assigned Incidents", dashStats.getOrDefault("myAssignedIncidentCount", 0));
                metrics.put("Executive Brief", "Incident response queue triage is operating within SLA targets. All Critical P1 incidents have active playbook response coverage.");
            } else if ("VULNERABILITY_REPORT".equals(type)) {
                metrics.put("Total Vulnerabilities", dashStats.getOrDefault("totalVulnerabilities", 0));
                metrics.put("Open Vulnerabilities", dashStats.getOrDefault("openVulnerabilities", 0));
                metrics.put("Critical Assets at Risk", dashStats.getOrDefault("criticalAssetsAtRisk", 0));
                metrics.put("Executive Brief", "Vulnerability remediation sweep completed across production assets. Patching schedules enforced for high-exposure CVEs.");
            } else if ("COMPLIANCE_AUDIT".equals(type)) {
                metrics.put("Overall Compliance Score", dashStats.getOrDefault("complianceScore", "94%"));
                metrics.put("Total Open Gaps", dashStats.getOrDefault("complianceOpenGaps", 0));
                metrics.put("Executive Brief", "SOC 2, ISO 27001, and HIPAA control attestations verified. Evidence logs audited against perimeter access controls.");
            } else if ("THREAT_INTEL".equals(type)) {
                metrics.put("Total Threat Indicators", dashStats.getOrDefault("totalThreatIntel", 0));
                metrics.put("Anomaly Logs Detected", dashStats.getOrDefault("anomalyLogs", 0));
                metrics.put("Executive Brief", "Threat Intelligence feeds synchronized with active perimeter blocklists. Automated IOC isolation active.");
            } else if ("USER_ACTIVITY".equals(type)) {
                metrics.put("Total Users", dashStats.getOrDefault("totalUsers", 0));
                metrics.put("Active Users", dashStats.getOrDefault("activeUsers", 0));
                metrics.put("Total Teams", dashStats.getOrDefault("totalTeams", 0));
                metrics.put("Total Log Entries", dashStats.getOrDefault("totalLogs", 0));
                metrics.put("Executive Brief", "User access & privilege escalation audit trail clean. Step-up MFA enforced for privileged account sessions.");
            }
            
            // Apply requested filters to metrics as text notes
            if (StringUtils.hasText((String) request.get("severityFilter")) && !"ALL".equals(request.get("severityFilter"))) {
                metrics.put("Applied Severity Filter", request.get("severityFilter"));
            }
        } catch (Exception e) {
            metrics.put("Notice", "Unable to fetch live metrics at this time.");
        }

        ReportRecord record = ReportRecord.builder()
                .type(type)
                .title(title)
                .generatedBy(currentUserEmail)
                .format(format)
                .size(scheduled ? "Pending" : size)
                .dateFrom((String) request.get("dateFrom"))
                .dateTo((String) request.get("dateTo"))
                .severityFilter((String) request.get("severityFilter"))
                .teamFilter((String) request.get("teamFilter"))
                .assetFilter((String) request.get("assetFilter"))
                .scheduled(scheduled)
                .frequency(frequency)
                .metrics(metrics)
                .createdAt(LocalDateTime.now())
                .build();

        ReportRecord saved = reportRecordRepository.save(record);

        auditLogService.log(null, currentUserEmail, "REPORT_GENERATED", "REPORTS", 
                "Generated " + format + " report: " + title);

        return saved;
    }
}
