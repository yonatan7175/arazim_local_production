"""
Linux on-connection hook.

Invoked once by the manager each time we (re)connect to G2. Intentionally a
no-op for now so the manager's ON_CONNECTION_SCRIPTS entry resolves to a real
file instead of failing to launch. Put connection-time setup here later.
"""

if __name__ == "__main__":
    pass
