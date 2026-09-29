"""Owner-side admin: toggle RLS enforcement and inspect it.

    python -m tenantguard.admin rls on|off|status

Runs as tg_owner (OWNER_DATABASE_URL). The app role cannot run these.
"""

import sys

import psycopg

from app import config
from tenantguard.db import rls_status, set_rls


def main(argv: list[str]) -> None:
    if len(argv) != 2 or argv[0] != "rls" or argv[1] not in ("on", "off", "status"):
        sys.exit("usage: python -m tenantguard.admin rls on|off|status")
    with psycopg.connect(config.OWNER_DATABASE_URL, autocommit=True) as conn:
        if argv[1] != "status":
            set_rls(conn, argv[1] == "on")
        for table, (enabled, forced) in sorted(rls_status(conn).items()):
            print(f"{table:10} enabled={enabled} forced={forced}")


if __name__ == "__main__":
    main(sys.argv[1:])
