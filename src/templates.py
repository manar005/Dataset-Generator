# Shared representation templates. Available to both labels. Not profile-owned.

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class NamedTemplate:
    template_id: str
    pattern: str


FROM_TEMPLATES = (
    NamedTemplate("from_addr_only", "{address}"),
    NamedTemplate("from_angle", "{display} <{address}>"),
    NamedTemplate("from_quoted", '"{display}" <{address}>'),
)

REPLY_TO_TEMPLATES = (
    NamedTemplate("reply_addr_only", "{address}"),
    NamedTemplate("reply_angle", "{display} <{address}>"),
    NamedTemplate("reply_quoted", '"{display}" <{address}>'),
)

RETURN_PATH_TEMPLATES = (
    NamedTemplate("rp_angle", "<{address}>"),
    NamedTemplate("rp_bare", "{address}"),
)

RECEIVED_TEMPLATES = (
    NamedTemplate(
        "recv_esmtps",
        "from {helo} ({helo} [{ip}]) by {mx} with ESMTPS id {rid}; {date}",
    ),
    NamedTemplate(
        "recv_esmtp",
        "from {helo} ([{ip}]) by {mx} with ESMTP id {rid} for <{rcpt}>; {date}",
    ),
    NamedTemplate(
        "recv_short",
        "from {helo} by {mx} with SMTP; {date}",
    ),
)

AUTH_RESULTS_TEMPLATES = (
    NamedTemplate(
        "auth_semicolon",
        "{authserv}; {tokens}",
    ),
    NamedTemplate(
        "auth_arc_style",
        "i=1; {authserv}; {tokens}",
    ),
)

RECEIVED_SPF_TEMPLATES = (
    NamedTemplate(
        "spf_paren",
        "{result} ({domain}: sender designated {ip} as permitted sender) identity=mailfrom; client-ip={ip}; envelope-from={mailfrom}",
    ),
    NamedTemplate(
        "spf_short",
        "{result} ({domain}: {detail})",
    ),
)

PLAIN_BODY_TEMPLATES = (
    NamedTemplate("plain_verbatim", "{body}{url_block}"),
    NamedTemplate("plain_spaced", "{body}\n{url_block}"),
)

HTML_BODY_TEMPLATES = (
    NamedTemplate(
        "html_pre",
        "<html><body><pre>{body_html}</pre>{url_block}</body></html>",
    ),
    NamedTemplate(
        "html_div",
        "<html><body><div>{body_html}</div>{url_block}</body></html>",
    ),
)

ATTACHMENT_NAME_TEMPLATES = (
    NamedTemplate("att_notes_txt", "notes.txt"),
    NamedTemplate("att_readme_txt", "readme.txt"),
    NamedTemplate("att_data_csv", "data.csv"),
    NamedTemplate("att_notes_js", "notes.js"),
    NamedTemplate("att_update_hta", "update.hta"),
    NamedTemplate("att_macro_docm", "form.docm"),
)

URL_STRUCTURE_TEMPLATES = (
    NamedTemplate("url_https_host", "https://{host}{path}"),
    NamedTemplate("url_http_host", "http://{host}{path}"),
    NamedTemplate("url_http_ip", "http://{host}{path}"),
)


def header_template_bundle_id(
    from_id: str,
    reply_id: str | None,
    return_path_id: str | None,
    received_id: str,
    auth_id: str | None,
    spf_id: str | None,
) -> str:
    parts = [from_id, reply_id or "noreply", return_path_id or "norp", received_id, auth_id or "noauth", spf_id or "nospf"]
    return "+".join(parts)
