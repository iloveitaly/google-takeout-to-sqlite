import click
import sqlite_utils
import sqlite_utils
import zipfile
from . import utils
from . import email


@click.group()
@click.version_option()
def cli():
    "Save data from Google Takeout to a SQLite database"


@cli.command(name="my-activity")
@click.argument(
    "db_path",
    type=click.Path(file_okay=True, dir_okay=False, allow_dash=False),
    required=True,
)
@click.argument(
    "zip_path",
    type=click.Path(file_okay=True, dir_okay=False, allow_dash=False),
    required=True,
)
def my_activity(db_path, zip_path):
    "Import all My Activity data from Takeout zip to SQLite"
    db = sqlite_utils.Database(db_path)
    zf = zipfile.ZipFile(zip_path)
    utils.save_my_activity(db, zf)


@cli.command(name="location-history")
@click.argument(
    "db_path",
    type=click.Path(file_okay=True, dir_okay=False, allow_dash=False),
    required=True,
)
@click.argument(
    "zip_path",
    type=click.Path(file_okay=True, dir_okay=False, allow_dash=False),
    required=True,
)
def location_history(db_path, zip_path):
    "Import all Location History data from Takeout zip to SQLite"
    db = sqlite_utils.Database(db_path)
    zf = zipfile.ZipFile(zip_path)
    utils.save_location_history(db, zf)


@cli.command(name="mbox")
@click.argument(
    "db_path",
    type=click.Path(file_okay=True, dir_okay=False, allow_dash=False),
    required=True,
)
@click.argument(
    "mbox_path",
    type=click.Path(file_okay=True, dir_okay=False, allow_dash=False),
    required=True,
)
@click.option("--views", is_flag=True, help="Create additional materialized views")
@click.option("--prefix", help="Prefix for mbox table names")
def my_mbox(db_path, mbox_path, views, prefix):
    """
    Import all emails from Gmail mbox to SQLite

    Usage:  google-takeout-to-sqlite mbox mygmail.db /path/to/gmail.mbox
    """
    db = sqlite_utils.Database(db_path)

    email.save_emails(db, mbox_path, prefix)

    if views:
        email.create_views(db, prefix)
