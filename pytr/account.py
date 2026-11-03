import sys
import time
from getpass import getpass

import requests

from . import credential_store
from .api import TradeRepublicApi, account_kind, account_name
from .utils import get_logger


def print_accounts(tr):
    """List the accounts of this login, one per line: type, name, customer id and state.

    `--account` takes the type, the name or, where those are not unique, the customer id.
    """
    rows = [
        (
            account_kind(r),
            account_name(r),
            str(r.get("customerId") or ""),
            "your own account" if r.get("relationshipType") == "SELF" else str(r.get("accountState") or ""),
        )
        for r in tr.relationships()
    ]
    if not rows:
        return ""
    heading = ("TYPE", "NAME", "CUSTOMER ID", "STATE")
    widths = [max(len(heading[i]), max(len(row[i]) for row in rows)) for i in range(4)]
    all_rows = [heading] + rows
    return "\n".join("  ".join(f"{cell:<{width}}" for cell, width in zip(row, widths)).rstrip() for row in all_rows)


def login(phone_no=None, pin=None, store_credentials=False, waf_token="playwright", v2=False, account=None):
    """
    Handle credentials parameters and store to credentials file if requested.
    If no parameters are set but are needed then ask for input

    `account` selects another account of this login, e.g. a company account.
    """
    log = get_logger(__name__)
    save_cookies = True

    stored = None
    if phone_no is None:
        try:
            stored = credential_store.load_credentials()
        except credential_store.SecretStoreError as e:
            log.error(f"Could not read the stored credentials: {e}")

    if stored is not None:
        phone_no, pin = stored
        phone_no_masked = phone_no[:-8] + "********"
        log.info(f"Using the stored credentials. Phone: {phone_no_masked}")
    else:
        if phone_no is None:
            print("Please enter your TradeRepublic phone number in the format +4912345678:")
            phone_no = input()

        if pin is None:
            print("Please enter your TradeRepublic pin:")
            pin = getpass(prompt="Pin (Input is hidden):")

        if store_credentials:
            try:
                credential_store.store_credentials(phone_no, pin)
                log.info(f"Stored the credentials encrypted in {credential_store.BASE_DIR}, key in the system keyring")
            except credential_store.SecretStoreError as e:
                log.error(f"Credentials and session are not stored: {e}")
                save_cookies = False
        else:
            save_cookies = False

    tr = TradeRepublicApi(phone_no=phone_no, pin=pin, save_cookies=save_cookies, waf_token=waf_token, use_v2_login=v2)

    # Use same login as app.traderepublic.com
    if not tr.resume_websession():
        try:
            countdown = tr.initiate_weblogin()
        except ValueError as e:
            log.fatal(str(e))
            sys.exit(1)
        request_time = time.time()
        if v2:
            if tr.weblogin_needs_authenticator:
                code = input("Enter the code from your authenticator app: ")
            else:
                print(f"Confirm the login in your Trade Republic app. (Countdown: {countdown})")
                code = None
        else:
            print("Enter the code you received to your mobile app as a notification.")
            print(f"Enter nothing if you want to receive the (same) code as SMS. (Countdown: {countdown})")
            code = input("Code: ")
            if code == "":
                countdown = countdown - (time.time() - request_time)
                for remaining in range(int(countdown)):
                    print(
                        f"Need to wait {int(countdown - remaining)} seconds before requesting SMS...",
                        end="\r",
                    )
                    time.sleep(1)
                print()
                tr.resend_weblogin()
                code = input("SMS requested. Enter the confirmation code:")
        tr.complete_weblogin(code)
        log.info("Logged in.")

    # Also proves the session works. The settings themselves are personal data and stay out of the log.
    tr.settings()

    if account is not None:
        try:
            tr.switch_account(account)
        except ValueError as e:
            log.fatal(str(e))
            sys.exit(1)
        except requests.exceptions.HTTPError as e:
            status = e.response.status_code if e.response is not None else "unknown"
            log.fatal(f"Trade Republic refused to switch to account {account!r} (status {status}).")
            sys.exit(1)
    return tr
