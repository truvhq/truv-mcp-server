import json
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
from auth import Auth0Provider, get_applicant_id_from_token
from truv import TruvClient

from starlette.requests import Request
from starlette.responses import JSONResponse, RedirectResponse, Response

secret = os.environ.get("API_SECRET")
client_id = os.environ.get("API_CLIENT_ID")
product_type = os.environ.get("API_PRODUCT_TYPE", "income")
# TODO: get applicant_id from the OAuth flow
#applicant_id = "9578fe626502428eaf1f45b9ec7c8bdb"

if not secret or not client_id:
    raise Exception("Environment MUST contains 'API_SECRET' and 'API_CLIENT_ID'")

api_client = TruvClient(
    secret=secret,
    client_id=client_id,
    product_type=product_type,
)


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
    find_users = api_client.find_user(external_applicant_id)
    if not find_users.get("results"):
        raise ValueError("No applicant id found")
    applicant_id = find_users.get("results", [])[0].get("id")
    
    if not applicant_id:
        raise ValueError("Could not determine applicant ID from authentication token")
    
    return applicant_id


# Initialize Auth0 provider
auth_provider = Auth0Provider()

# Create an MCP server with OAuth support (Auth0 broker)
mcp = FastMCP(
    "Truv MCP",
    auth_server_provider=auth_provider,
    auth=AuthSettings(
        issuer_url="http://localhost:8000",  # Our MCP server acts as the OAuth Authorization Server
        required_scopes=[],  # adjust if you want to require specific scopes
        client_registration_options=ClientRegistrationOptions(enabled=True),  # Enable dynamic client registration
    ),
    host="localhost",
    port=8000,
    debug=True,
)

# Note: CORS might be handled automatically by FastMCP for OAuth flows
# If we need explicit CORS configuration, we'll need to use FastMCP's approach

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

#@mcp.tool()
#def collect_data(email: str):
#    order = api_client.create_order(email)
#    return order['id']

@mcp.tool()
async def list_accounts() -> str:
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
def get_income_report_authenticated(link_id: str) -> str:
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
        return api_client.get_link_report(link_id, 'income')
    except ValueError as e:
        return f"Error: {str(e)}"


@mcp.tool()
def get_bank_transactions(link_id: str) -> str:
    """
    Retrieve all bank accounts and transactions for a specific account link using the Truv API.
    
    Args:
        link_id (str): The unique identifier for the account link to retrieve accounts and transactions for.
        
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
        # Make the actual Truv API call with authenticated applicant_id
        # For now, using the existing api_client but should be updated to use applicant_id
        return api_client.get_bank_transactions(link_id)
    except ValueError as e:
        return f"Error: {str(e)}"

@mcp.prompt()
def find_savings() -> str:
    """
    Analyze transactions from all linked accounts for a given applicant and summarize spending by category.
    
    This prompt should:
        - Retrieve all transactions from the applicant's linked accounts.
        - Identify and group transactions by their spend categories (e.g., groceries, utilities, entertainment).
        - Summarize total spending per category, highlighting major areas of expenditure.
    
    Args:
        None (applicant context is assumed from the environment)
    
    Returns:
        A summary string or structured data that lists spend categories and the total amount spent in each category for the applicant.
    
    Usage:
        Use this prompt to provide applicants or analysts with an overview of spending habits, identify major expense categories, or support budgeting and financial planning.
    """
    return f"Where can I reduce spending?"


if __name__ == "__main__":
    # Initialize and run the server
    mcp.run(transport='sse')
