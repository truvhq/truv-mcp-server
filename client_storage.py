import json
import logging
from typing import Dict
from pathlib import Path
from mcp.shared.auth import OAuthClientInformationFull

# ---------------------------------------------------------------------------
# Persistent client storage
# ---------------------------------------------------------------------------
CLIENTS_FILE = Path("oauth_clients.json")

def load_clients() -> Dict[str, OAuthClientInformationFull]:
    """Load clients from persistent storage."""
    if not CLIENTS_FILE.exists():
        return {}
    
    try:
        with open(CLIENTS_FILE, 'r') as f:
            data = json.load(f)
        
        # Convert dict back to OAuthClientInformationFull objects
        clients = {}
        for client_id, client_data in data.items():
            clients[client_id] = OAuthClientInformationFull(**client_data)
        return clients
    except Exception as e:
        logging.info(f"Error loading clients: {e}")
        return {}

def save_clients(clients: Dict[str, OAuthClientInformationFull]) -> None:
    """Save clients to persistent storage."""
    #try:
        # Convert OAuthClientInformationFull objects to dict for JSON serialization
    data = {}
    for client_id, client in clients.items():
        data[client_id] = client.model_dump(mode='json')
    
    with open(CLIENTS_FILE, 'w') as f:
        json.dump(data, f, indent=2)
    #except Exception as e:
    #    logging.info(f"Error saving clients: {e}")

def clear_all_clients() -> None:
    """Clear all registered clients - useful for forcing re-registration."""
    if CLIENTS_FILE.exists():
        CLIENTS_FILE.unlink()
    logging.info("All client registrations cleared")
