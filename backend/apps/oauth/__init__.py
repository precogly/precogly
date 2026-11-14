"""Lets a user decide which MCP clients may act on their Precogly account.

django-oauth-toolkit validates authorization requests and issues grants and tokens. Its
authorize view also asks the user for consent, but it renders a Django template and
requires a Django session. Precogly asks for consent in its React application instead,
so the page is not a separately styled copy of the interface. That application signs
users in with a JWT, which the toolkit's view cannot use, so the consent step is rebuilt
here, starting with the table that holds a validated request until the user allows or
denies the MCP client access to their account.

This app gives out tokens. The MCP server, which checks a token on every request, lives
in `apps.core.mcp`.
"""
