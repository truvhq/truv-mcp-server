import logging
from uuid import uuid4
from typing import Dict
import requests
from datetime import datetime, timedelta
from faker import Faker

fake = Faker()


class TruvClient:
    api_url = "https://prod.truv.com/v1/"

    def __init__(
        self, client_id: str, secret: str, product_type: str, api_url: str = None
    ):
        self.headers = {
            "X-Access-Client-Id": client_id,
            "X-Access-Secret": secret,
            "Content-Type": "application/json;charset=UTF-8",
            "Accept": "application/json",
        }
        if api_url:
            self.api_url = api_url
        self.product_type = product_type

        self.applicant_ids: Dict[str, str] = {}  # Map external user ids to applicant ids
        self.links: Dict[str, set[str]] = {}  # Map applicant ids to links

    def _request(self, method, endpoint, **kwargs) -> dict:
        headers = kwargs.pop("headers", {})
        headers.update(self.headers)

        url = self.api_url + endpoint

        try:
            response = requests.request(
                method,
                url,
                headers=headers,
                **kwargs,
            )

            response.raise_for_status()
            return response.json()

        except requests.exceptions.HTTPError as err:
            logging.exception("API Request Error: %s", err.response.text)
            raise err

    def post(self, endpoint: str, **kwargs) -> dict:
        return self._request("post", endpoint, **kwargs)

    def get(self, endpoint: str, **kwargs) -> dict:
        return self._request("get", endpoint, **kwargs)

    def create_user(self, **kwargs) -> dict:
        logging.info("TRUV: Requesting new user from https://prod.truv.com/v1/users/")
        payload = {
            "external_user_id": f"qs-{uuid4().hex}",
            "first_name": fake.first_name(),
            "last_name": fake.last_name(),
            "email": fake.email(domain="example.com"),
            **kwargs,
        }
        return self.post("users/", json=payload)
    
    def find_user(self, external_user_id: str) -> dict:
        logging.info("TRUV: Searching for user from https://prod.truv.com/v1/users/")

        if external_user_id in self.applicant_ids:
            return self.applicant_ids[external_user_id]

        find_users = self.get(f"users/?external_user_id={external_user_id}&list_links=false")
        if not find_users.get("results"):
            raise ValueError("No applicant id found")
        applicant_id = find_users.get("results", [])[0].get("id")

        self.applicant_ids[external_user_id] = applicant_id

        return applicant_id

    def create_user_bridge_token(self, user_id: str) -> dict:
        logging.info(
            "TRUV: Requesting user bridge token from https://prod.truv.com/v1/users/{user_id}/tokens"
        )
        logging.info("TRUV: User ID - %s", user_id)

        payload = {
            "product_type": self.product_type,
            "tracking_info": "1338-0111-A",
        }

        if self.product_type in ["deposit_switch", "pll"]:
            payload["account"] = {
                "account_number": "16002600",
                "account_type": "checking",
                "routing_number": "12345678",
                "bank_name": fake.company(),
            }

            if self.product_type == "pll":
                payload["account"].update(
                    {
                        "deposit_type": "amount",
                        "deposit_value": "100",
                    }
                )
        return self.post(f"users/{user_id}/tokens/", json=payload)
    
    def create_order(self, email: str) -> dict:
        logging.info(
            "TRUV: Requesting order from https://prod.truv.com/v1/orders/"
        )

        payload = {
            "order_number": f"qs-{uuid4().hex}",
            "first_name": fake.first_name(),
            "last_name": fake.last_name(),
            "email": email,
            "products": [self.product_type]
        }
        
        return self.post("orders/", json=payload)

    
    def list_links(self, applicant_id: str) -> dict:
        logging.info(
            f"TRUV: Requesting links for {applicant_id}"
            f"https://prod.truv.com/v1/links/?user_id={applicant_id}",
        )
        links = self.get(f"links/?user_id={applicant_id}")
        if applicant_id not in self.links:
            self.links[applicant_id] = set()
        for link in links.get("results", []):
            self.links[applicant_id].add(link.get("id"))

        return links

    def get_link_report(self, link_id: str, product_type: str) -> dict:
        logging.info(
            f"TRUV: Requesting {product_type} report from "
            f"https://prod.truv.com/v1/links/{link_id}/{product_type}/report",
        )
        logging.info("TRUV: Link ID - %s", link_id)

        report = self.get(f"links/{link_id}/{product_type}/report")

        if report.get("status") == "done":
            del report['pdf_report']
            del report['access_token']
            for emp in report.get("employments", []):
                emp['statements'] = emp['statements'][:6]
                del emp['bank_accounts']
                del emp['derived_fields']
                del emp['missing_data_fields']
                del emp['profile']
                for st in emp['statements']:
                    del st['file']
                    del st['check_number']
                    del st['derived_fields']
                    del st['missing_data_fields']
                for w2 in emp.get("w2s", []):
                    del w2['file']
        return report
    

    def get_bank_transactions(self, link_id: str, days: int = 30) -> dict:
        logging.info(
            f"TRUV: Requesting transactions from "
            f"https://prod.truv.com/v1/links/{link_id}/transactions",
        )
        logging.info("TRUV: Link ID - %s", link_id)

        # Use provided transacted_at_from or calculate from days
       
        from_date = datetime.now() - timedelta(days=days)
        transacted_at_from = from_date.strftime("%Y-%m-%dT%H:%M:%SZ")

        # Initialize pagination variables
        page = 1
        all_transactions = []
        all_accounts = []
        
        while True:
            # Make API request with pagination
            endpoint = f"links/{link_id}/transactions?page_size=100&page={page}&transacted_at_from={transacted_at_from}"
            page_data = self.get(endpoint)
            
            # Collect accounts (they should be the same across pages, but we'll take from first page)
            if page == 1 and page_data.get('accounts'):
                all_accounts = page_data['accounts']
            
            # Collect transactions from this page
            if page_data.get('transactions'):
                all_transactions.extend(page_data['transactions'])
            
            # Check if there are more pages
            if not page_data.get('next'):
                break
                
            page += 1

        # Create the final response structure
        report = {
            'count': len(all_transactions),

            'accounts': all_accounts,
            'transactions': all_transactions
        }

        # Apply data filtering/cleanup
        if report:
            # Limit transactions to 100 if you want to keep the original behavior
            #report['transactions'] = report['transactions'][:100]
            for tr in report['transactions']:
                # Remove sensitive/unnecessary fields
                for field in ['id', 'external_id', 'check_number', 'location', 'transacted_at', 'merchant_category_code', 'memo', 'created_at', 'updated_at']:
                    if field in tr:
                        del tr[field]
        return report
