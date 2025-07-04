import asyncio
import logging
import os
from dotenv import load_dotenv


logging.basicConfig(level=logging.INFO)
load_dotenv()
# server.py
from mcp.server.fastmcp import FastMCP
from mcp.server.fastmcp import Context
from mcp.server.auth.middleware.auth_context import get_access_token

from mcp.server.auth.settings import AuthSettings, ClientRegistrationOptions
from auth import Auth0Provider, get_applicant_id_from_token, get_user_info
from truv import TruvClient

from starlette.requests import Request
from starlette.responses import JSONResponse, RedirectResponse, Response
from client_storage import load_clients

secret = os.environ.get("API_SECRET")
client_id = os.environ.get("API_CLIENT_ID")
product_type = os.environ.get("API_PRODUCT_TYPE", "income")

if not secret or not client_id:
    raise Exception("Environment MUST contains 'API_SECRET' and 'API_CLIENT_ID'")

api_client = TruvClient(
    secret=secret,
    client_id=client_id,
    product_type=product_type,
)


# Initialize Auth0 provider
auth_provider = Auth0Provider()


async def register_clients():
    clients = load_clients()
    for client_id, client_info in clients.items():
        await auth_provider.register_client(client_info)

asyncio.run(register_clients())

# Create an MCP server with OAuth support (Auth0 broker)
mcp = FastMCP(
    "Truv MCP",
    auth_server_provider=auth_provider,
    auth=AuthSettings(
        issuer_url=os.environ.get("ISSUER_URL", "http://localhost:8000"),  # Our MCP server acts as the OAuth Authorization Server
        required_scopes=[],  # adjust if you want to require specific scopes
        client_registration_options=ClientRegistrationOptions(enabled=True),  # Enable dynamic client registration
    ),
    host=os.environ.get("HOST", "localhost"),
    port=os.environ.get("PORT", 8000),
    debug=True,
)

# Note: CORS might be handled automatically by FastMCP for OAuth flows
# If we need explicit CORS configuration, we'll need to use FastMCP's approach

def get_authenticated_applicant_id() -> str:
    """
    Extract the applicant_id from the authenticated user's access token.
        
    Returns:
        str: The applicant_id for the authenticated user.
        
    Raises:
        ValueError: If no authentication token is found or applicant_id cannot be determined.
    """
     
    access_token = get_access_token()
    if not access_token:
        raise ValueError("Not authenticated")
    external_applicant_id = get_applicant_id_from_token(access_token.token)

    if not external_applicant_id:
        raise ValueError("No external user id found")
    
    applicant_id = api_client.find_user(external_applicant_id)
    
    if not applicant_id:
        raise ValueError("No connected accounts found. Please connect your accounts first.")
    
    return applicant_id

def get_applicant_info() -> dict:
    """
    Get applicant info for a given access token.
    """
    access_token = get_access_token()
    if not access_token:
        raise ValueError("Not authenticated")
    user_info = get_user_info(access_token.token)
    return user_info

# Add the Auth0 callback endpoint
@mcp.custom_route("/auth/callback", methods=["GET"])
async def auth_callback(request: Request):
    """Handle Auth0 callback and complete the OAuth flow"""
    code = request.query_params.get("code")
    state = request.query_params.get("state")
    
    if not code or not state:
        return JSONResponse({"error": "Missing code or state parameter"}, status_code=400)
    
    try:
        # Use our Auth0Provider to handle the callback
        redirect_url = await auth_provider.handle_auth0_callback(state, code)
        return RedirectResponse(url=redirect_url)
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=400)

@mcp.tool()
async def connect_accounts(company_names: list[str] = None, bank_names: list[str] = None) -> str:
    """
    Connect additional financial or payroll accounts by generating a temporary order page HTML.
    This HTML should be displayed in a modal as an artifact.

    This tool allows users to connect additional bank accounts, payroll systems, 
    or other financial data sources to expand their available data collection. 
    The tool returns an HTML page where users can authenticate and 
    authorize access to their additional accounts.

    Optionally, specific company names where the user works or bank names where 
    the user has accounts can be provided to streamline the connection process 
    and focus data collection efforts.
    
    Args:
        company_names (list[str]): Optional list of employer/company names to 
            prioritize during the account connection process.
        bank_names (list[str]): Optional list of financial institution names to 
            prioritize during the account connection process.

    Returns:
        str: An html page where the user can connect their additional accounts.
    """
    applicant_id = None
    try:
        applicant_id = get_authenticated_applicant_id()
    except ValueError as e:
        logging.info(f"Applicant id not found: {e}")

    user_info = get_applicant_info()
    print(user_info, "user_info")

    applicant = {
        'id': applicant_id,
        'first_name': user_info.get('nickname'),
        'last_name': user_info.get('name'),
        'external_user_id': user_info.get('sub'),
    }

    order = api_client.create_order(applicant, company_names, bank_names)
    

    # Return full-screen iframe with proper styling
    return f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Connect Your Accounts - Truv</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        html, body {{
            height: 100%;
            width: 100%;
            overflow: hidden;
        }}
        
        .iframe-container {{
            position: fixed;
            top: 0;
            left: 0;
            width: 100vw;
            height: 100vh;
            z-index: 9999;
        }}
        
        .truv-iframe {{
            width: 100%;
            height: 100%;
            border: none;
            display: block;
        }}
    </style>
</head>
<body>
    <div class="iframe-container">
        <iframe 
            class="truv-iframe" 
            src="{order['short_share_url']}" 
            title="Connect Your Accounts - Truv"
            allow="camera; microphone; geolocation; payment; autoplay; encrypted-media; fullscreen"
            allowfullscreen
            webkitallowfullscreen
            mozallowfullscreen
            sandbox="allow-same-origin allow-scripts allow-forms allow-top-navigation allow-popups allow-modals allow-orientation-lock allow-pointer-lock allow-presentation allow-top-navigation-by-user-activation"
        ></iframe>
    </div>
</body>
</html>
"""

@mcp.tool()
async def list_accounts() -> dict:
    """
    Get a list of all accounts (links) for an applicant using the Truv API.

    Reference: https://docs.truv.com/reference/links-list
    
    Args:
        None
        
    Returns:
        List of account link objects for the applicant, as returned by Truv.
        Each object contains details about a connected account (link) with ID, provider name, and status.
        
    Usage:
        Use this function to retrieve all account links associated with a specific applicant.
        This can be useful for displaying connected accounts, managing connections, or initiating further data requests for a given applicant.
    """
    try:
        applicant_id = get_authenticated_applicant_id()
        
        # Now make the Truv API call with the applicant_id
        # This is where you would make the actual API call to Truv
        return api_client.list_links(applicant_id)
    except ValueError as e:
        return f"Error: {str(e)}"
    except Exception as e:
        return f"Unexpected error: {str(e)}"


@mcp.tool()
def get_income_report_authenticated(link_id: str) -> dict:
    """
    Get a personalized income report for a specific account link using the Truv API.
    
    Args:
        link_id (str): The unique identifier for the account link to retrieve the income report for.
        
    Returns:
        JSON string containing the income and employment report for the specified link.
        The report typically includes details such as income summary, employment history, employer information, pay statements, and verification status.
        
    Usage:
        Use this function to obtain a comprehensive income and employment report for a given account link.
        This is useful for verifying applicant income, employment status, and generating reports for underwriting or compliance purposes.
    """
    try:
        applicant_id = get_authenticated_applicant_id()
        if link_id not in api_client.links[applicant_id]:
            raise ValueError("Link not found")
        return api_client.get_link_report(link_id, 'income')
    except ValueError as e:
        return f"Error: {str(e)}"


@mcp.tool()
def get_bank_transactions(link_id: str, days: int = 30) -> dict:
    """
    Retrieve all bank accounts and transactions for a specific account link using the Truv API.
    
    Args:
        link_id (str): The unique identifier for the account link to retrieve accounts and transactions for.
        days (int): The number of days to retrieve transactions for. Defaults to 30.
    Returns:
        JSON object containing:
            - count (int): Total number of transactions.
            - next (str): URL to the next page of results, if any.
            - previous (str): URL to the previous page of results, if any.
            - accounts (list): List of account objects, each with fields such as:
                - id (str): Account ID
                - created_at (str): Creation timestamp
                - updated_at (str): Last update timestamp
                - type (str): Account type (e.g., CHECKING)
                - subtype (str): Account subtype (e.g., MONEY_MARKET)
                - mask (str): Account number mask
                - nickname (str): Account nickname
                - balances (dict): Balance details (currency_code, balance, available_balance, credit_limit)
            - transactions (list): List of transaction objects, each with fields such as:
                - id (str): Transaction ID
                - created_at (str): Creation timestamp
                - updated_at (str): Last update timestamp
                - account_id (str): Associated account ID
                - external_id (str): External transaction key
                - amount (str): Transaction amount
                - currency_code (str): Currency code
                - check_number (str): Check number, if applicable
                - categories (list): List of transaction categories
                - description (str): Transaction description
                - status (str): Transaction status (e.g., POSTED)
                - type (str): Transaction type (e.g., DEBIT)
                - posted_at (str): Date posted
                - transacted_at (str): Date transacted
                - memo (str): Memo field
                - merchant_category_code (int): Merchant category code
                - location (dict): Location details (latitude, longitude)
        
    Usage:
        Use this function to retrieve all bank accounts and their associated transactions for a given account link.
        This is useful for financial analysis, transaction history review, and account management.
    """
    try:
        applicant_id = get_authenticated_applicant_id()
        if link_id not in api_client.links[applicant_id]:
            raise ValueError("Link not found")
        # Make the actual Truv API call with authenticated applicant_id
        # For now, using the existing api_client but should be updated to use applicant_id
        return api_client.get_bank_transactions(link_id, days)
    except ValueError as e:
        return f"Error: {str(e)}"

if __name__ == "__main__":
    # Initialize and run the server
    mcp.run(transport='sse') # streamable-http is for production
