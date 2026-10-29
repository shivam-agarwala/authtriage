from datetime import datetime

import pytest

from authtriage.parser import parse_lines

HOST = "web-01"


def parse(*lines, year=2026):
    return list(parse_lines(list(lines), year=year))


def test_failed_password_syslog():
    (event,) = parse(f"Oct 29 10:11:12 {HOST} sshd[123]: Failed password for root "
                     "from 203.0.113.5 port 44321 ssh2")
    assert event.kind == "failed_password"
    assert (event.ip, event.user, event.port, event.pid) == ("203.0.113.5", "root", 44321, 123)
    assert event.ts == datetime(2026, 10, 29, 10, 11, 12)
    assert event.invalid_user is False
    assert event.line_no == 1


def test_failed_password_invalid_user_flag():
    (event,) = parse(f"Oct 29 10:11:12 {HOST} sshd[123]: Failed password for invalid user "
                     "oracle from 203.0.113.5 port 44321 ssh2")
    assert event.invalid_user is True and event.user == "oracle"


def test_padded_single_digit_day():
    (event,) = parse(f"Oct  9 03:04:05 {HOST} sshd[1]: Invalid user test from 203.0.113.5 port 1")
    assert event.ts == datetime(2026, 10, 9, 3, 4, 5)


def test_iso_timestamp_is_normalised_to_utc():
    (event,) = parse(f"2026-10-29T10:11:12+05:30 {HOST} sshd[9]: Accepted password for alice "
                     "from 198.51.100.9 port 50122 ssh2")
    assert event.kind == "accepted"
    assert event.ts == datetime(2026, 10, 29, 4, 41, 12)


def test_pam_failure_and_preauth_variants():
    events = parse(
        f"Oct 29 10:11:10 {HOST} sshd[1]: pam_unix(sshd:auth): authentication failure; "
        "logname= uid=0 euid=0 tty=ssh ruser= rhost=203.0.113.5  user=root",
        f"Oct 29 10:11:13 {HOST} sshd[1]: Connection closed by authenticating user root "
        "203.0.113.5 port 44321 [preauth]",
        f"Oct 29 10:11:14 {HOST} sshd[2]: Disconnected from invalid user git "
        "203.0.113.77 port 33001 [preauth]",
        f"Oct 29 10:11:15 {HOST} sshd[3]: Connection closed by 203.0.113.9 port 1 [preauth]",
    )
    assert [e.kind for e in events] == ["pam_failure"] + ["preauth_disconnect"] * 3
    assert events[0].user == "root" and events[0].ip == "203.0.113.5"
    assert events[2].user == "git"
    assert events[3].user is None and events[3].ip == "203.0.113.9"


def test_year_rollover_across_december():
    events = parse(f"Dec 31 23:59:59 {HOST} sshd[1]: Failed password for root from 1.2.3.4 port 1 ssh2",
                   f"Jan  1 00:00:04 {HOST} sshd[1]: Failed password for root from 1.2.3.4 port 2 ssh2",
                   year=2026)
    assert events[0].ts.year == 2026 and events[1].ts.year == 2027


def test_non_sshd_and_junk_lines_are_skipped():
    events = parse(
        f"Oct 29 10:00:00 {HOST} sudo:   alice : TTY=pts/0 ; COMMAND=/bin/ls",
        f"Oct 29 10:00:01 {HOST} CRON[22]: pam_unix(cron:session): session opened for user root",
        "this line has no timestamp at all",
        "",
        f"Oct 29 10:00:02 {HOST} sshd[5]: Server listening on 0.0.0.0 port 22.",
    )
    assert events == []


@pytest.mark.parametrize("message,kind", [
    ("Invalid user admin from 203.0.113.5 port 1", "invalid_user"),
    ("Accepted publickey for alice from 198.51.100.9 port 1 ssh2: RSA SHA256:abc", "accepted"),
    ("Failed publickey for bob from 198.51.100.9 port 1 ssh2", "failed_password"),
])
def test_message_kinds(message, kind):
    (event,) = parse(f"Oct 29 10:00:00 {HOST} sshd[7]: {message}")
    assert event.kind == kind
