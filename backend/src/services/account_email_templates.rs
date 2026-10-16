//! Account-lifecycle email templates.
//!
//! Pure functions: given trusted inputs (username, deadline, URLs derived from
//! the configured app base URL), they produce a subject, a plain-text body, and
//! an HTML body. They read no files, query no database, call no provider, and
//! escape every interpolated value. The same inputs always produce the same
//! output, so a test can assert the whole artifact and a retry never drifts.
//!
//! Visual direction: dark charcoal surfaces, ember/orange restraint accents,
//! editorial serif headlines, clean sans-serif body. Table-based layout so the
//! message survives Gmail, Outlook, and mobile clients. No external fonts,
//! no tracking pixels, no JavaScript, no animations.

use crate::services::email_artifact::escape_html;

/// One rendered account-lifecycle message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountEmail {
    pub subject: String,
    pub text_body: String,
    pub html_body: String,
}

/// Shared outer shell: dark container, muted border, predictable structure.
/// `app_base_url` is the trusted configured origin used only for footer links.
/// `inner` is injected by each template; `text_body` is the plain-text content.
fn shell(
    app_base_url: &str,
    title: &str,
    inner: &str,
    text_prefix: &str,
    text_body: &str,
) -> AccountEmail {
    let base = app_base_url.trim_end_matches('/');
    let html = format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{0}</title>
<style>
  body {{ margin:0; padding:0; background:#0b0c10; color:#e5e7eb; font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif; }}
  table {{ border-spacing:0; }}
  .wrap {{ width:100%; background:#0b0c10; }}
  .card {{ max-width:600px; margin:0 auto; background:#111827; border:1px solid #1f2937; }}
  .pad {{ padding:40px 32px; }}
  .accent {{ height:4px; background:#f97316; }}
  h1 {{ margin:0 0 16px 0; font-family:Georgia,"Times New Roman",Times,serif; font-size:22px; color:#f5f5f4; line-height:1.3; }}
  p {{ margin:0 0 16px 0; font-size:15px; line-height:1.6; color:#cbd5e1; }}
  .lead {{ font-size:16px; color:#e2e8f0; }}
  .btn {{ display:inline-block; background:#f97316; color:#ffffff; text-decoration:none; border-radius:8px; font-weight:600; font-size:15px; padding:12px 24px; }}
  .btn:hover {{ background:#ea580c; }}
  .muted {{ color:#94a3b8; font-size:13px; }}
  .footer {{ border-top:1px solid #1f2937; padding-top:24px; margin-top:24px; font-size:12px; color:#64748b; }}
  @media (max-width: 480px) {{ .card {{ border-radius:0; }} .pad {{ padding:28px 20px; }} }}
</style>
</head>
<body>
<table role="presentation" class="wrap" width="100%" cellpadding="0" cellspacing="0">
  <tr>
    <td align="center" style="padding:32px 16px;">
      <table role="presentation" class="card" width="100%" cellpadding="0" cellspacing="0">
        <tr><td class="accent"></td></tr>
        <tr><td class="pad">
          {1}
          <table role="presentation" class="footer" width="100%" cellpadding="0" cellspacing="0">
            <tr>
              <td>
                <p class="muted">{2} · <a href="{3}" style="color:#94a3b8;text-decoration:none;">{3}</a><br>
                Fire Crow — evidence-driven security auditing.<br>
                You received this because it concerns your Fire Crow account.</p>
              </td>
            </tr>
          </table>
        </td></tr>
      </table>
    </td>
  </tr>
</table>
</body>
</html>"#,
        escape_html(title),
        inner,
        escape_html(title),
        escape_html(base),
    );

    let mut text_full = format!(
        "Fire Crow — {0}\n{1}\n\n---\nFire Crow by Next Lab\n{2}\nYou received this because it concerns your Fire Crow account.\n",
        escape_html_plain(title),
        text_prefix,
        escape_html_plain(base),
    );
    text_full.push_str(text_body);

    AccountEmail {
        subject: format!("Fire Crow — {0}", escape_html_plain(title)),
        text_body: text_full,
        html_body: html,
    }
}

/// Plain-text newline guard: collapse line breaks so body text cannot mangle
/// headers or inject layout into the plain-text part.
fn escape_html_plain(value: &str) -> String {
    value.replace(['\r', '\n'], " ")
}

/// Welcome email — sent once, after the account-creation transaction succeeds.
pub fn welcome_email(app_base_url: &str, username: &str) -> AccountEmail {
    let start_url = format!("{}/console/overview", app_base_url.trim_end_matches('/'));
    let inner = format!(
        r#"<h1>Welcome to Fire Crow, {0}</h1>
<p class="lead">Your account is ready. Fire Crow scans your GitHub repositories with Gitleaks, Semgrep, and OSV-Scanner inside throwaway containers, then freezes every finding into a ledger no one can edit after the run.</p>
<p>Open your console and paste a repository URL to start your first audit:</p>
<p style="margin:24px 0;"><a href="{1}" class="btn">Open console</a></p>
<p class="muted">This deployment runs on the free tier as a demo: the API may take up to a minute to answer on the first request, and live scanner execution stays disabled until the audited Docker boundary is provisioned.</p>"#,
        escape_html(username),
        escape_html(&start_url)
    );
    shell(
        app_base_url,
        "Welcome to Fire Crow",
        &inner,
        "Your account is ready.",
        &format!("Start your first audit: {0}", escape_html(&start_url)),
    )
}

/// Account-deletion request confirmation.
pub fn deletion_requested_email(
    app_base_url: &str,
    username: &str,
    deadline_rfc3339: &str,
    cancel_url: &str,
) -> AccountEmail {
    let inner = format!(
        r#"<h1>Account deletion requested</h1>
<p class="lead">We received your request to delete your Fire Crow account, {0}.</p>
<p>Your account is <strong>not deleted yet</strong>. It is scheduled for deletion on <strong>{1}</strong>. Until then you can sign in and cancel at any time.</p>
<p>What happens at deletion:</p>
<ul style="margin:0 0 16px 0;padding-left:20px;color:#cbd5e1;">
  <li style="margin-bottom:8px;">Your account record and credentials are removed.</li>
  <li style="margin-bottom:8px;">Sessions and API tokens are revoked.</li>
  <li style="margin-bottom:8px;">Scan results and reports tied to your account are anonymized or retained per our retention policy.</li>
</ul>
<p style="margin:24px 0;"><a href="{2}" class="btn">Cancel deletion</a></p>
<p class="muted">If you did not request this, no action is needed — the deletion will not proceed unless you confirm, and you can ignore this message.</p>"#,
        escape_html(username),
        escape_html(deadline_rfc3339),
        escape_html(cancel_url)
    );
    shell(
        app_base_url,
        "Account deletion requested",
        &inner,
        "Your account deletion has been requested.",
        &format!("Cancellation link: {0}", escape_html(cancel_url)),
    )
}

/// Account-deletion reminder — sent during the grace period before the deadline.
pub fn deletion_reminder_email(
    app_base_url: &str,
    username: &str,
    deadline_rfc3339: &str,
    cancel_url: &str,
) -> AccountEmail {
    let inner = format!(
        r#"<h1>Your account deletion is approaching</h1>
<p class="lead">Your Fire Crow account is scheduled for deletion on <strong>{0}</strong>.</p>
<p>You are inside the grace period and can still cancel. After the deadline, your account and its data are removed and the action cannot be undone.</p>
<p style="margin:24px 0;"><a href="{1}" class="btn">Cancel deletion</a></p>
<p class="muted">If you want to keep your account, cancel before the deadline. If you did not request deletion, ignore this message and contact support.</p>"#,
        escape_html(deadline_rfc3339),
        escape_html(cancel_url)
    );
    shell(
        app_base_url,
        "Account deletion approaching",
        &inner,
        "Your account deletion is approaching.",
        &format!(
            "Deadline: {0} · Cancellation link: {1}",
            escape_html(deadline_rfc3339),
            escape_html(cancel_url)
        ),
    )
}

/// Account-deletion completed — sent only after a verified deletion event.
pub fn deletion_completed_email(app_base_url: &str, username: &str) -> AccountEmail {
    let inner = format!(
        r#"<h1>Your Fire Crow account has been deleted</h1>
<p class="lead">Your account, {0}, has been deleted.</p>
<p>Your account record, credentials, and sessions have been removed. Scan results and reports tied to your account have been anonymized or retained where the law or our retention policy requires.</p>
<p class="muted">Some information may remain in backups and external processors for a limited period and is subject to separate retention policies — it is not part of your active account.</p>"#,
        escape_html(username)
    );
    shell(
        app_base_url,
        "Account deleted",
        &inner,
        "Your account has been deleted.",
        &format!(
            "Support: {0}/support",
            escape_html(app_base_url.trim_end_matches('/'))
        ),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn welcome_email_contains_username_and_console_link() {
        let email = welcome_email("https://app.example.com", "alice");
        assert!(email.subject.contains("Welcome to Fire Crow"));
        assert!(email.html_body.contains("Welcome to Fire Crow, alice"));
        assert!(email
            .html_body
            .contains("https://app.example.com/console/overview"));
        assert!(email.html_body.contains("class=\"btn\""));
        assert!(email
            .text_body
            .contains("https://app.example.com/console/overview"));
    }

    #[test]
    fn templates_escape_html_metacharacters() {
        let email = welcome_email("https://app.example.com", "<script>alert(1)</script>");
        assert!(!email.html_body.contains("<script>"));
        assert!(!email.text_body.contains("<script>"));
        assert!(email.html_body.contains("&lt;script&gt;"));
    }

    #[test]
    fn deletion_templates_carry_deadline_and_cancel_link() {
        let req = deletion_requested_email(
            "https://app.example.com",
            "bob",
            "2027-01-15T00:00:00Z",
            "https://app.example.com/account/cancel?token=abc",
        );
        let rem = deletion_reminder_email(
            "https://app.example.com",
            "bob",
            "2027-01-15T00:00:00Z",
            "https://app.example.com/account/cancel?token=abc",
        );
        let done = deletion_completed_email("https://app.example.com", "bob");

        for e in [&req, &rem, &done] {
            assert!(e.subject.contains("Fire Crow"));
            assert!(!e.text_body.is_empty());
            assert!(!e.html_body.is_empty());
        }
        assert!(req.html_body.contains("2027-01-15T00:00:00Z"));
        assert!(rem.html_body.contains("2027-01-15T00:00:00Z"));
        assert!(req.text_body.contains("Cancellation link:"));
        assert!(rem.text_body.contains("Cancellation link:"));
        assert!(req.html_body.contains("Cancel deletion"));
        assert!(rem.html_body.contains("Cancel deletion"));
        assert!(done.text_body.contains("has been deleted"));
    }

    #[test]
    fn no_bare_credentials_or_tokens_in_subject() {
        let email = welcome_email("https://app.example.com", "alice");
        assert!(!email.subject.to_lowercase().contains("password"));
        assert!(!email.subject.to_lowercase().contains("token"));
        assert!(!email.subject.to_lowercase().contains("secret"));
    }
}
