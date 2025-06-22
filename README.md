# Get started with Truv MCP

1. Clone the repository
```shell
git clone https://github.com/truvhq/truv-mcp-server.git
```

2. Open `truv-mcp-server` directory and create `.env` file:
```shell
cd truv-mcp-server
make env
```

3. Update the values in `.env` file by adding in your Client ID and Sandbox Access key:
```
# please set your <Client ID>
API_CLIENT_ID=

# please set your <Access key>
API_SECRET=


4. Run the MCP server:
uv run --project . mcp run server.py
