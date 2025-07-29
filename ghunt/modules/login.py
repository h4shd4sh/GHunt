import os
from typing import *

import httpx
from pathlib import Path

from ghunt import globals as gb
from ghunt.helpers.utils import *
from ghunt.helpers import auth
from ghunt.objects.base import GHuntCreds
from ghunt.errors import GHuntInvalidSession


async def check_and_login(as_client: httpx.AsyncClient, clean: bool=False, oauth_token: Optional[str] = None, master_token: Optional[str] = None) -> None:
    """Check the users credentials validity, and generate new ones."""

    ghunt_creds = GHuntCreds()

    if clean:
        creds_path = Path(ghunt_creds.creds_path)
        if creds_path.is_file():
            creds_path.unlink()
            print(f"[+] Credentials file at {creds_path} deleted!")
        else:
            print(f"Credentials file at {creds_path} doesn't exist, no need to delete.")
        exit(os.EX_OK)

    if not as_client:
        as_client = get_httpx_client()

    try:
        ghunt_creds = await auth.load_and_auth(as_client, help=False)
        is_master_token_valid = await auth.check_master_token(as_client, ghunt_creds.android.master_token)
        cookies_valid = await auth.check_cookies(as_client, ghunt_creds.cookies)
        osids_valid = await auth.check_osids(as_client, ghunt_creds.cookies, ghunt_creds.osids)

        print("[+] Existing credentials validation:")
        print(f"  - Master token: {'✅' if is_master_token_valid else '❌'}")
        print(f"  - Cookies: {'✅' if cookies_valid else '❌'}")
        print(f"  - OSIDs: {'✅' if osids_valid else '❌'}")

        new_gen_inp = input("\nDo you want to create a new session? (Y/n) ").lower()
        if new_gen_inp != "y":
            await as_client.aclose()
            exit(os.EX_OK)

    except GHuntInvalidSession:
        print("[-] Invalid session detected.")

    # Si no hay token y no estamos en modo interactivo, lanzamos diálogo
    if not oauth_token or not master_token:
        oauth_token, master_token = auth.auth_dialog()

    print(f"\n[+] Got OAuth2 token => {oauth_token}")
    master_token, services, owner_email, owner_name = await auth.android_master_auth(as_client, oauth_token)

    print("\n[Connected account]")
    print(f"Name : {owner_name}")
    print(f"Email : {owner_email}")
    gb.rc.print("\n🔑 [underline]A master token has been generated for your account and saved in the credentials file[/underline], please keep it safe as if it were your password, because it gives access to a lot of Google services, and with that, your personal information.", style="bold")
    print(f"Master token services access : {', '.join(services)}")

    # Feed the GHuntCreds object
    ghunt_creds.android.master_token = master_token
    ghunt_creds.android.authorization_tokens = {}  # Reset
    ghunt_creds.cookies = {"a": "a"}  # Dummy data
    ghunt_creds.osids = {"a": "a"}    # Dummy data

    print("Generating cookies and osids...")
    await auth.gen_cookies_and_osids(as_client, ghunt_creds)
    print("[+] Cookies and osids generated!")

    ghunt_creds.save_creds()

    await as_client.aclose()

