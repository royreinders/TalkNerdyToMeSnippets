# TalkNerdyToMeSnippets

Code snippets accompanying my talk "Talk Nerdy To Me: Orchestrating Red Team Infrastructure". This repository conains:
* oc2bot.py: Outflank C2 bot that stores information from implants in a SQLite database and feteches queued commands and shedules them for execution.
* oc2mcp.py: The MCP component of the Outflank C2 integration, which fetches information from the OC2 logs and oc2bot database to provide an LLM with implant information and inserts to be executed commands in the oc2bot database.
* initdb.py: Initialization script for the oc2bot database.
* nginxmcp.py: MCP server that integrates with NGINX, providing features to an LLM such as adding/deleting VHOSTS, requesting certificates, reading access logs and checking an existing payload for basic OPSEC issues.
* mcp_client.py: A small and simple client to talk to a local LLM and the OC2 MCP server.
