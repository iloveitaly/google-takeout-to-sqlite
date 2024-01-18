import email
import traceback
import re
import os
from bs4 import BeautifulSoup
from rich.progress import BarColumn, DownloadColumn, Progress, TextColumn
from email import policy, header, headerregistry
import datetime

# This policy is similar to policy.default but without strict header parsing.
# Many emails contain invalid headers that cannot be parsed according to spec.
header_factory = headerregistry.HeaderRegistry(use_default_map=False)
header_factory.map_to_type(
    "content-disposition", headerregistry.ContentDispositionHeader
)
email_policy = policy.EmailPolicy(header_factory=header_factory)


# in order to parse large mbox files, we need to use raw file IO instead of the stdlib mailbox
# until the entire mbox is parsed we won't process any messages
def parse_mbox(mbox_file):
    with open(mbox_file, "rb") as f:
        f.seek(0, os.SEEK_END)
        file_len = f.tell()
        f.seek(0)

        progress = Progress(
            TextColumn("[bold blue]{task.description}", justify="right"),
            BarColumn(bar_width=None),
            "[progress.percentage]{task.percentage:>3.1f}%",
            "•",
            DownloadColumn(),
        )

        with progress:
            task = progress.add_task("[red]Processing...", total=file_len)

            delivery_date = ""
            message_id = ""
            lines = []

            while True:
                line = f.readline()

                progress.update(task, advance=len(line))

                is_new_record = line.startswith(b"From ")
                is_eof = len(line) == 0

                if is_eof or is_new_record:
                    message = b"".join(lines)
                    if message:
                        yield delivery_date, message_id, email.message_from_bytes(
                            message, policy=email_policy
                        )
                else:
                    lines.append(line)

                if is_new_record:
                    (message_id, delivery_date) = re.match(
                        r"^From (\w+)@xxx (.+)\r\n", line.decode("utf-8")
                    ).groups()
                    lines = []
                elif is_eof:
                    break


def get_mbox(mbox_file):
    num_errors = 0

    # These are all the Gmail email fields available
    # ['X-GM-THRID', 'X-Gmail-Labels', 'Delivered-To', 'Received', 'Received',
    # 'Return-Path', 'Received', 'Received-SPF', 'Authentication-Results',
    # 'Received', 'Mailing-List', 'Precedence', 'List-Post', 'List-Help',
    # 'List-Unsubscribe', 'List-Subscribe', 'Delivered-To', 'Received',
    # 'Message-ID', 'Date', 'From', 'To', 'MIME-Version', 'Content-Type',
    # 'Content-Transfer-Encoding', 'X-Nabble-From', 'X-pstn-neptune',
    # 'X-pstn-levels', 'X-pstn-settings', 'X-pstn-addresses', 'Subject']

    for delivery_date, gmail_message_id, email in parse_mbox(mbox_file):
        try:
            message = {}
            message["Message-Id"] = email["Message-Id"]
            if message["Message-Id"] is None:
                message["Message-Id"] = gmail_message_id
            message["X-GM-THRID"] = email["X-GM-THRID"]
            message["X-Gmail-Labels"] = email["X-Gmail-Labels"]

            message["From"] = get_email_header(email, "From")
            message["To"] = get_email_header(email, "To")
            message["Cc"] = get_email_header(email, "Cc")
            message["Bcc"] = get_email_header(email, "Bcc")
            message["Subject"] = get_email_header(email, "Subject")

            if "Date" in email:
                message["date"] = parse_mail_date(email["Date"])
            else:
                message["date"] = parse_mail_date(delivery_date)

            message["body"] = get_email_body(email)

            yield message
        except (TypeError, ValueError, AttributeError, LookupError) as e:
            # How does this project want to handle logging? For now we're just
            # printing out variables
            num_errors = num_errors + 1
            print("Errors: {}".format(num_errors))
            print(traceback.format_exc())
            continue


# assume format of `First Last <email@domain.com>`, `email@domain.com`, or `<email@domain.com>`
def extract_email(from_header):
    if from_header is None:
        return None

    match = re.match(r"(.*)<(.*)>", from_header)
    if match:
        return match.group(2)

    match = re.match(r"<(.*)>", from_header)
    if match:
        return match.group(1)

    return from_header


def extract_emails(to_header) -> list[str]:
    if to_header is None:
        return []

    emails = []
    for email in to_header.split(","):
        emails.append(extract_email(email))

    return emails


def extract_labels(labels_header):
    if labels_header is None:
        return None

    return labels_header.split(",")


def normalize_mbox_message(message):
    return {
        "id": message["Message-Id"],
        "gmail_thread_id": message["X-GM-THRID"],
        "labels": extract_labels(message["X-Gmail-Labels"]),
        "from": message["From"],
        "from_email": extract_email(message["From"]),
        "to": message["To"],
        "to_emails": extract_emails(message["To"]),
        "cc": message["Cc"],
        "cc_emails": extract_emails(message["Cc"]),
        "bcc": message["Bcc"],
        "bcc_emails": extract_emails(message["Bcc"]),
        "all_recipients": extract_emails(message["To"])
        + extract_emails(message["Cc"])
        + extract_emails(message["Bcc"]),
        "subject": message["Subject"],
        "date": message["date"],
        "body": message["body"],
    }


from ipdb import iex


@iex
def save_emails(db, mbox_file):
    """
    Import Gmail mbox from google takeout
    """

    # if not db["mbox_emails"].exists():
    #     db["mbox_emails"].create(
    #         {
    #             "id": str,
    #             "X-GM-THRID": str,
    #             "X-Gmail-Labels": str,
    #             "from": str,
    #             "to": str,
    #             "subject": str,
    #             "when": str,
    #             "body": str,
    #         },
    #         pk="id",
    #     )

    db["mbox_emails"].upsert_all(
        (normalize_mbox_message(message) for message in get_mbox(mbox_file)),
        pk="id",
        alter=True,
    )

    print("Finished loading emails into {}.".format(mbox_file))

    print('Enabling full text search on "body" and "Subject" fields')
    db["mbox_emails"].enable_fts(["body", "Subject"])

    print("Finished!")


def get_email_header(message, name, failobj=None):
    # get will either return a str, email.header.Header, or None.
    # This function converts the Header to a str if one is returned.
    value = message.get(name)
    if value is None:
        return failobj
    else:
        try:
            return decode_rfc_2047_str(value)
        except:
            # If the value is invalid, return the un-decoded string.
            return value


def decode_rfc_2047_str(value):
    parts = []

    for part, enc in header.decode_header(value):
        try:
            part = part.decode(enc or "utf-8")
        except LookupError:  # encoding not found
            part = part.decode("utf-8")
        except AttributeError:  # part was already a str
            pass

        parts.append(part)

    return "".join(parts)


def get_email_body(message):
    """
    return the email body contents
    """
    try:
        body = message.get_body(preferencelist=("plain", "html"))
    except AttributeError:
        # Work around https://bugs.python.org/issue42892
        return message.get_payload(decode=True)

    if not body:
        return None

    try:
        content = body.get_content()
    except:
        # If headers are malformed, get_content may throw an exception.
        # Fall back to get_payload method that doesn't use the ContentManager.
        content = body.get_payload(decode=True)

    if body.get_content_type() == "text/html":
        doc = BeautifulSoup(content, features="lxml")
        return doc.get_text(strip=True, separator=" ")
    else:
        return content


def parse_mail_date(mail_date):
    datetime_tuple = email.utils.parsedate_tz(mail_date)
    if not datetime_tuple:
        return ""

    unix_time = email.utils.mktime_tz(datetime_tuple)
    mail_date_iso8601 = datetime.datetime.utcfromtimestamp(unix_time).isoformat(" ")
    return mail_date_iso8601
