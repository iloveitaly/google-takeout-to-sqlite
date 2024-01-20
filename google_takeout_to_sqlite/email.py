import email
import traceback
import re
import os
from bs4 import BeautifulSoup
from rich.progress import BarColumn, DownloadColumn, Progress, TextColumn
from email import policy, header, headerregistry
import datetime

from sqlite_utils import Database

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
                    # NOTE add len(line) > 10_000 to test a small subset of a large inbox
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


from nameparser import HumanName


def name_details(name):
    # remove any quotes or spaces from the beginning or end
    name = name.strip("'\" ")
    name_parts = HumanName(name)

    return {
        "name": name,
        "firstName": name_parts.first,
        "middleName": name_parts.middle,
        "lastName": name_parts.last,
    }


# assume format of `First Last <email@domain.com>`, `email@domain.com`, or `<email@domain.com>`
def extract_email(from_header, with_name=False):
    """
    "Amazon.com" <shipment-tracking@amazon.com>
    """
    if from_header is None:
        return None

    from_header = from_header.strip()

    match = re.match(r"(.*)<(.*)>", from_header)
    if match:
        if with_name:
            return name_details(match.group(1)) | {"email": match.group(2).strip()}
        return match.group(2)

    match = re.match(r"<(.*)>", from_header)
    if match:
        extracted_email = match.group(1).strip()

        if "'" in extracted_email or '"' in extracted_email:
            breakpoint()

        if with_name:
            return {"name": None, "email": extracted_email}
        return extracted_email

    # this case is just a raw email address
    if with_name:
        return {"name": None, "email": from_header}

    return from_header


def extract_email_from_tuple(from_tuple: tuple[str, str], with_details: bool):
    """
    email.utils.getaddresses([to_header]) =>

       ('Flip Howard', 'flip@lucidprivateoffices.com')
       ('davidskiviatsr@gmail.com', 'davidskiviatsr@gmail.com')
    """

    if from_tuple[0] == "" and from_tuple[1] == "":
        return None

    if not with_details:
        # then just return the email
        return from_tuple[1]

    has_name = from_tuple[0] != from_tuple[1] and from_tuple[0]

    name = from_tuple[0]
    name = name.strip("'\" ")

    email = from_tuple[1]
    email = email.strip("'\" ").lower()

    if "@" not in email:
        # not a valid email, probably spam or some other garbage
        return None

    # extract domain from email
    domain = email.split("@")[1]

    if not has_name:
        return {
            "domain": domain,
            "email": email,
        }

    return name_details(name) | {
        "domain": domain,
        "email": email,
    }


def extract_emails(to_header, with_details=False) -> list[str]:
    if to_header is None:
        return []

    emails = []

    # naive "," split will break on names with commas
    email_list = email.utils.getaddresses([to_header])

    for contact_tuple in email_list:
        emails.append(
            extract_email_from_tuple(contact_tuple, with_details=with_details)
        )

    return emails


def extract_labels(labels_header):
    if labels_header is None:
        return None

    return labels_header.split(",")


def normalize_mbox_message(message):
    # TODO allow certain labels (like spam) to be excluded

    return {
        "id": message["Message-Id"],
        "gmail_thread_id": message["X-GM-THRID"],
        "labels": extract_labels(message["X-Gmail-Labels"]),
        "from": message["From"],
        "from_email": extract_email(message["From"]),
        "to": message["To"],
        "to_contacts": extract_emails(message["To"], with_details=True),
        "to_emails": extract_emails(message["To"]),
        "cc": message["Cc"],
        "cc_contacts": extract_emails(message["Cc"], with_details=True),
        "cc_emails": extract_emails(message["Cc"]),
        "bcc": message["Bcc"],
        "bcc_emails": extract_emails(message["Bcc"]),
        "bcc_contacts": extract_emails(message["Bcc"], with_details=True),
        "all_recipients": extract_emails(message["To"])
        + extract_emails(message["Cc"])
        + extract_emails(message["Bcc"]),
        "all_contacts": extract_emails(message["To"], with_details=True)
        + extract_emails(message["Cc"], with_details=True)
        + extract_emails(message["Bcc"], with_details=True),
        "subject": message["Subject"],
        "date": message["date"],
        "body": message["body"],
    }


def generate_table_name(prefix):
    root_name = "mbox_emails"

    if prefix:
        root_name = f"{prefix}_{root_name}"

    return root_name


def create_views(db: Database, prefix):
    """
    Create additional materialized views
    """

    print("Creating views...")

    table_name = generate_table_name(prefix)
    formatted_prefix = f"{prefix}_" if prefix else ""

    address_book = f"""
CREATE VIEW {formatted_prefix}address_book AS
SELECT
    json_extract(contact.value, '$.email') AS email,
    json_extract(contact.value, '$.name') AS name,
    json_extract(contact.value, '$.firstName') AS first_name,
    json_extract(contact.value, '$.lastName') AS last_name,
    json_extract(contact.value, '$.domain') AS domain,
    MAX({table_name}.date) AS last_contacted,
    COUNT(*) AS count_contact
FROM {table_name},
     json_each({table_name}.all_contacts) AS contact
GROUP BY json_extract(contact.value, '$.email');
"""

    db.conn.execute("DROP VIEW IF EXISTS address_book")
    db.conn.execute(address_book)

    # determine whose email inbox this is
    owner_email_query = f"""
SELECT json_extract(to_emails, '$[0]') as owner_email
FROM {table_name}
WHERE to_emails != '[]'
GROUP BY to_emails
ORDER BY COUNT(*) DESC
LIMIT 1;
"""
    owner_email = db.execute(owner_email_query).fetchone()[0]

    to_address_book_query = f"""
CREATE VIEW {formatted_prefix}to_address_book AS
SELECT
    json_extract(contact.value, '$.email') AS email,
    json_extract(contact.value, '$.name') AS name,
    json_extract(contact.value, '$.firstName') AS first_name,
    json_extract(contact.value, '$.lastName') AS last_name,
    json_extract(contact.value, '$.domain') AS domain,
    MAX({table_name}.date) AS last_contacted,
    COUNT(*) AS count_contact
FROM {table_name},
     json_each({table_name}.to_contacts) AS contact
WHERE from_email = '{owner_email}'
GROUP BY json_extract(contact.value, '$.email')
"""

    db.execute(to_address_book_query)

    personal_to_address_book_query = f"""
CREATE VIEW {formatted_prefix}filtered_to_address_book AS
SELECT *
FROM {formatted_prefix}to_address_book
WHERE DOMAIN NOT LIKE '%.%.%'
  AND DOMAIN NOT IN ('amazonses.com', 'craigslist.org', 'amazon.com', 'mandrillapp.com', 'fut.io', 'followup.cc', 'todoist.net', 'tmomail.net')
  AND NOT (
    EMAIL LIKE 'customer%' OR
    EMAIL LIKE 'support%' OR
    EMAIL LIKE 'info%' OR
    EMAIL LIKE 'billing%' OR
    EMAIL LIKE 'care%' OR
    EMAIL LIKE 'hi%' OR
    EMAIL LIKE 'bounce%' OR
    EMAIL LIKE 'hello%' OR
    EMAIL LIKE 'newsletter%' OR
    EMAIL LIKE 'team%' OR
    EMAIL LIKE 'service%' OR
    EMAIL LIKE 'reply%' OR
    EMAIL LIKE 'noreply%' OR
    EMAIL LIKE 'notification%' OR
    EMAIL LIKE 'help%' OR
    EMAIL LIKE 'sales%'
  );
"""
    owner_email = db.execute(personal_to_address_book_query)


def save_emails(db, mbox_file, prefix):
    """
    Import Gmail mbox from google takeout
    """

    table_name = generate_table_name(prefix)

    # TODO if no messages are processed, the table is not created
    db[table_name].upsert_all(
        (normalize_mbox_message(message) for message in get_mbox(mbox_file)),
        pk="id",
        alter=True,
    )

    print("Finished loading emails into {}.".format(mbox_file))

    print('Enabling full text search on "body" and "Subject" fields')
    db[table_name].enable_fts(["body", "Subject"])

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
