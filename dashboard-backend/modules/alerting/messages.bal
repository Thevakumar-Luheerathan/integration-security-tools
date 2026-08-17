// Pure message-formatting logic - kept separate from chat.bal (I/O) and alert.bal (wiring) so
// the actual message content can be unit tested without a real Chat webhook (see
// tests/messages_test.bal). Moved from the standalone choreo-alerting component - see diff.bal's
// header comment.

import integration_security_tools/dashboard_backend.model as db;

function findingLine(db:Finding f) returns string {
    string package = packageDisplayName(f);
    string pkgVersion = f.package_version is string ? string `@${f.package_version ?: ""}` : "";
    string versionLabel = f.ballerina_version ?: (f.plugin_branch ?: "");
    return string `  - *${f.severity}* ${f.cve} in ${package}${pkgVersion} (${f.'source}, ${versionLabel})`;
}

function unattendedIssueLine(UnattendedIssue u) returns string {
    int wholeDays = <int>u.ageDays;
    return string `  - *${u.severity}* #${u.issueNumber} (${u.packageDisplay}) - open ${wholeDays} day(s), still unattended`;
}

public function formatImmediateAlert(db:Finding[] newCriticalOrHigh, db:ScanStatus[] newlyFailed, boolean staleTransition,
        UnattendedIssue[] newlyUnattended) returns string? {
    if newCriticalOrHigh.length() == 0 && newlyFailed.length() == 0 && !staleTransition && newlyUnattended.length() == 0 {
        return (); // nothing worth an immediate ping - the weekly digest still covers everything
    }

    string message = "*Ballerina vulnerability scan - immediate alert*\n";

    if staleTransition {
        message += "\n:warning: The scan pipeline hasn't produced fresh results recently - it may be failing silently. Check the workflow run history.\n";
    }

    if newlyFailed.length() > 0 {
        message += string `\n*${newlyFailed.length()} scan(s) newly failing:*\n`;
        foreach var f in newlyFailed {
            string versionLabel = f.ballerina_version ?: (f.plugin_branch ?: "");
            message += string `  - ${versionLabel}/${f.'source}: ${f.'error ?: "unknown error"}\n`;
        }
    }

    if newCriticalOrHigh.length() > 0 {
        message += string `\n*${newCriticalOrHigh.length()} new CRITICAL/HIGH finding(s):*\n`;
        foreach var f in newCriticalOrHigh {
            message += findingLine(f) + "\n";
        }
    }

    if newlyUnattended.length() > 0 {
        message += string `\n*${newlyUnattended.length()} open issue(s) just crossed 1 week unattended:*\n`;
        foreach var u in newlyUnattended {
            message += unattendedIssueLine(u) + "\n";
        }
    }

    return message;
}

public function formatWeeklyDigest(db:CombinedReport report, int totalOpen, int criticalCount, int highCount, int acceptedRiskCount) returns string {
    string message = "*Ballerina vulnerability scan - weekly digest*\n\n";
    message += string `As of ${report.generated_at}: *${totalOpen}* open finding(s) across ${report.versions.length()} version line(s) `;
    message += string `(*${criticalCount}* critical, *${highCount}* high).\n`;

    if acceptedRiskCount > 0 {
        message += string `*${acceptedRiskCount}* additional finding(s) are accepted risk (see .trivyignore) and excluded from the counts above.\n`;
    }

    db:ScanStatus[] failing = failedScanStatuses(report);
    if failing.length() > 0 {
        message += string `\n:warning: ${failing.length()} scan(s) currently failing:\n`;
        foreach var f in failing {
            string versionLabel = f.ballerina_version ?: (f.plugin_branch ?: "");
            message += string `  - ${versionLabel}/${f.'source}: ${f.'error ?: "unknown error"}\n`;
        }
    }

    message += "\nSee the dashboard for full detail and per-package tracking issues.";
    return message;
}
