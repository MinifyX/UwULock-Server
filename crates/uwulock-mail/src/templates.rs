//! What the mails say, in German and English.
//!
//! Short, and the same shape every time: a line that says what this is, the one thing to do
//! with it (a code, a link), and a line on what to do if it was not you. Plain text first; the
//! HTML is the same text with a little layout, and everything that comes from outside the server
//! — a hint, a device name — is escaped before it goes in.

use crate::Language;

/// Every mail the server writes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Mail {
    /// From the admin portal: the mail server works.
    Test,
    /// Somebody may make an account, with the link.
    Invitation {
        link: String,
        /// The server's address, as people know it: `vault.example.com`.
        server: String,
        /// Who invited, if a person did.
        invited_by: Option<String>,
        /// The day the link stops working, already written for the reader.
        expires: String,
    },
    /// A code for logging in, when two-step login goes by mail.
    TwoFactorCode { code: String },
    /// A code that proves the address works, before two-step login by mail is turned on.
    TwoFactorSetup { code: String },
    /// A code for moving the account to this address.
    EmailChange { code: String },
    /// The master password hint, if there is one.
    PasswordHint { hint: Option<String> },
    /// A device logged in for the first time.
    NewDevice { device: String, ip: String, time: String },
    /// Two-step login was turned off with the recovery code.
    RecoveryUsed,
}

struct Text {
    subject: String,
    /// Paragraphs. The one that is `highlight` is shown large: the code, or the link.
    lines: Vec<String>,
    highlight: Option<String>,
    button: Option<(String, String)>,
    footer: String,
}

impl Mail {
    /// Subject, plain text and HTML.
    pub fn render(&self, language: Language) -> (String, String, String) {
        let text = self.text(language);
        let mut plain = String::new();
        let mut html = String::new();
        for line in &text.lines {
            plain.push_str(line);
            plain.push_str("\n\n");
            html.push_str(&format!("<p style=\"margin:0 0 16px\">{}</p>", escape(line)));
            if let Some(highlight) = text.highlight.as_ref().filter(|_| line == &text.lines[0]) {
                plain.push_str(highlight);
                plain.push_str("\n\n");
                html.push_str(&format!(
                    "<p style=\"margin:0 0 16px;font-size:28px;font-weight:700;letter-spacing:4px;\
                     font-family:ui-monospace,Menlo,Consolas,monospace\">{}</p>",
                    escape(highlight)
                ));
            }
            if let Some((label, link)) = text.button.as_ref().filter(|_| line == &text.lines[0]) {
                plain.push_str(link);
                plain.push_str("\n\n");
                html.push_str(&format!(
                    "<p style=\"margin:0 0 16px\"><a href=\"{link}\" style=\"display:inline-block;padding:12px 20px;\
                     border-radius:10px;background:#8b5cf6;color:#ffffff;text-decoration:none;font-weight:600\">{label}</a></p>\
                     <p style=\"margin:0 0 16px;font-size:13px;color:#6b7280;word-break:break-all\">{link}</p>",
                    link = escape(link),
                    label = escape(label)
                ));
            }
        }
        plain.push_str("-- \n");
        plain.push_str(&text.footer);
        plain.push('\n');
        let html = format!(
            "<!doctype html><html><body style=\"margin:0;padding:24px;background:#f5f3ff;\
             font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;color:#1f2937;line-height:1.5\">\
             <div style=\"max-width:520px;margin:0 auto;background:#ffffff;border-radius:16px;padding:28px\">\
             <p style=\"margin:0 0 20px;font-weight:700;font-size:18px;color:#7c3aed\">UwULock</p>{html}\
             <p style=\"margin:24px 0 0;font-size:12px;color:#9ca3af\">{}</p></div></body></html>",
            escape(&text.footer)
        );
        (text.subject, plain, html)
    }

    fn text(&self, language: Language) -> Text {
        let de = language == Language::De;
        let footer = if de {
            "Diese Mail kommt von deinem UwULock Server.".to_string()
        } else {
            "This mail comes from your UwULock Server.".to_string()
        };
        let not_you = |de: bool| {
            if de {
                "Warst du das nicht? Dann ändere dein Master-Passwort und sag der Verwaltung deines Servers Bescheid."
                    .to_string()
            } else {
                "Wasn't you? Change your master password and tell whoever runs your server.".to_string()
            }
        };
        match self {
            Mail::Test => Text {
                subject: if de { "Testmail von UwULock" } else { "Test mail from UwULock" }.into(),
                lines: vec![if de {
                    "Wenn du das liest, kann dein UwULock Server Mails verschicken. (◕‿◕✿)"
                } else {
                    "If you can read this, your UwULock Server can send mail. (◕‿◕✿)"
                }
                .into()],
                highlight: None,
                button: None,
                footer,
            },
            Mail::Invitation { link, server, invited_by, expires } => {
                let who = invited_by.clone();
                Text {
                    subject: if de { format!("Einladung zu UwULock auf {server}") } else { format!("You're invited to UwULock on {server}") },
                    lines: vec![
                        match (de, who) {
                            (true, Some(who)) => format!("{who} hat dich zu UwULock auf {server} eingeladen. Leg hier dein Konto an:"),
                            (true, None) => format!("Du bist zu UwULock auf {server} eingeladen. Leg hier dein Konto an:"),
                            (false, Some(who)) => format!("{who} invited you to UwULock on {server}. Create your account here:"),
                            (false, None) => format!("You're invited to UwULock on {server}. Create your account here:"),
                        },
                        if de {
                            format!("Der Link gilt bis {expires}. Danach braucht es eine neue Einladung.")
                        } else {
                            format!("The link works until {expires}. After that, you need a new invitation.")
                        },
                        if de {
                            "Dein Master-Passwort verlässt nie dein Gerät: Merk es dir gut, niemand kann es dir zurückholen."
                        } else {
                            "Your master password never leaves your device: remember it well, nobody can get it back for you."
                        }
                        .into(),
                    ],
                    highlight: None,
                    button: Some((if de { "Konto anlegen" } else { "Create account" }.into(), link.clone())),
                    footer,
                }
            }
            Mail::TwoFactorCode { code } => Text {
                subject: if de { format!("Dein Anmeldecode: {code}") } else { format!("Your login code: {code}") },
                lines: vec![
                    if de { "Hier ist dein Code für die Anmeldung bei UwULock:" } else { "Here is your code for logging in to UwULock:" }
                        .into(),
                    if de { "Er gilt 10 Minuten." } else { "It works for 10 minutes." }.into(),
                    not_you(de),
                ],
                highlight: Some(code.clone()),
                button: None,
                footer,
            },
            Mail::TwoFactorSetup { code } => Text {
                subject: if de { "Zwei-Schritt-Anmeldung per Mail einrichten" } else { "Set up two-step login by mail" }.into(),
                lines: vec![
                    if de {
                        "Mit diesem Code schaltest du die Zwei-Schritt-Anmeldung per Mail ein:"
                    } else {
                        "This code turns on two-step login by mail:"
                    }
                    .into(),
                    if de { "Er gilt 10 Minuten." } else { "It works for 10 minutes." }.into(),
                    not_you(de),
                ],
                highlight: Some(code.clone()),
                button: None,
                footer,
            },
            Mail::EmailChange { code } => Text {
                subject: if de { "Neue Adresse für UwULock bestätigen" } else { "Confirm your new address for UwULock" }.into(),
                lines: vec![
                    if de {
                        "Mit diesem Code ziehst du dein UwULock-Konto auf diese Adresse um:"
                    } else {
                        "This code moves your UwULock account to this address:"
                    }
                    .into(),
                    if de { "Er gilt 10 Minuten." } else { "It works for 10 minutes." }.into(),
                    if de {
                        "Hast du das nicht angefordert? Dann kannst du diese Mail einfach löschen."
                    } else {
                        "Didn't ask for this? Then just delete this mail."
                    }
                    .into(),
                ],
                highlight: Some(code.clone()),
                button: None,
                footer,
            },
            Mail::PasswordHint { hint } => Text {
                subject: if de { "Dein Master-Passwort-Hinweis" } else { "Your master password hint" }.into(),
                lines: match hint {
                    Some(hint) => vec![
                        if de { "Du hast dir diesen Hinweis zu deinem Master-Passwort hinterlegt:" } else { "This is the hint you left for your master password:" }
                            .into(),
                        hint.clone(),
                    ],
                    None => vec![if de {
                        "Du hast keinen Hinweis zu deinem Master-Passwort hinterlegt."
                    } else {
                        "You didn't leave a hint for your master password."
                    }
                    .into()],
                },
                highlight: None,
                button: None,
                footer,
            },
            Mail::NewDevice { device, ip, time } => Text {
                subject: if de { "Neue Anmeldung bei UwULock" } else { "New login to UwULock" }.into(),
                lines: vec![
                    if de {
                        format!("Ein neues Gerät hat sich bei deinem Konto angemeldet: {device}, von {ip}, am {time}.")
                    } else {
                        format!("A new device logged in to your account: {device}, from {ip}, on {time}.")
                    },
                    not_you(de),
                ],
                highlight: None,
                button: None,
                footer,
            },
            Mail::RecoveryUsed => Text {
                subject: if de { "Zwei-Schritt-Anmeldung ausgeschaltet" } else { "Two-step login turned off" }.into(),
                lines: vec![
                    if de {
                        "Mit deinem Wiederherstellungscode wurde gerade die Zwei-Schritt-Anmeldung deines Kontos ausgeschaltet."
                    } else {
                        "Your recovery code was just used to turn off two-step login for your account."
                    }
                    .into(),
                    if de {
                        "Richte sie im Web-Tresor wieder ein, damit dein Konto geschützt bleibt."
                    } else {
                        "Set it up again in the web vault, so your account stays protected."
                    }
                    .into(),
                    not_you(de),
                ],
                highlight: None,
                button: None,
                footer,
            },
        }
    }
}

fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_code_is_in_the_text_and_the_html() {
        let (subject, text, html) = Mail::TwoFactorCode { code: "042317".into() }.render(Language::De);
        assert!(subject.contains("042317"));
        assert!(text.contains("042317") && text.contains("10 Minuten"));
        assert!(html.contains("042317"));
    }

    #[test]
    fn an_invitation_carries_its_link() {
        let mail = Mail::Invitation {
            link: "https://vault.example.com/#/finish-signup?token=abc&email=nyu%40example.com".into(),
            server: "vault.example.com".into(),
            invited_by: Some("Mika".into()),
            expires: "2. Oktober 2026".into(),
        };
        let (subject, text, html) = mail.render(Language::De);
        assert!(subject.contains("vault.example.com"));
        assert!(text.contains("Mika hat dich") && text.contains("token=abc"));
        assert!(
            html.contains("href=\"https://vault.example.com/#/finish-signup?token=abc&amp;email=nyu%40example.com\"")
        );
        let (_, english, _) = mail.render(Language::En);
        assert!(english.contains("Mika invited you"));
    }

    #[test]
    fn what_comes_from_outside_is_escaped() {
        let (_, text, html) = Mail::PasswordHint { hint: Some("<b>cat</b> & \"dog\"".into()) }.render(Language::En);
        assert!(text.contains("<b>cat</b>"), "plain text stays as it is");
        assert!(html.contains("&lt;b&gt;cat&lt;/b&gt; &amp; &quot;dog&quot;"));
        assert!(!html.contains("<b>cat"));
    }

    #[test]
    fn every_mail_has_both_languages() {
        let mails = [
            Mail::Test,
            Mail::TwoFactorSetup { code: "1".into() },
            Mail::EmailChange { code: "1".into() },
            Mail::PasswordHint { hint: None },
            Mail::NewDevice { device: "Firefox".into(), ip: "192.0.2.1".into(), time: "now".into() },
            Mail::RecoveryUsed,
        ];
        for mail in mails {
            let (de, _, _) = mail.render(Language::De);
            let (en, _, _) = mail.render(Language::En);
            assert_ne!(de, en, "{mail:?}");
        }
    }
}
