import logging
from uuid import uuid4

import requests
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
            logging.info(
                "TRUV: Response: %s %s - %s:\n %s\n",
                method.upper(),
                url,
                response.status_code,
                response.content,
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

        return self.get(f"users/?external_user_id={external_user_id}&list_links=false")

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

    def get_access_token(self, public_token: str) -> dict:
        logging.info(
            "TRUV: Exchanging a public_token for an access_token from https://prod.truv.com/v1/link-access-tokens"
        )
        logging.info("TRUV: Public Token - %s", public_token)

        return self.post(
            "link-access-tokens/",
            json={
                "public_token": public_token,
            },
        )
    
    def list_links(self, applicant_id: str) -> dict:
        logging.info(
            f"TRUV: Requesting links for {applicant_id}"
            f"https://prod.truv.com/v1/links/?user_id={applicant_id}",
        )

        return self.get(f"links/?user_id={applicant_id}")

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
    

    def get_bank_transactions(self, link_id: str) -> dict:
        logging.info(
            f"TRUV: Requesting transactions from "
            f"https://prod.truv.com/v1/links/{link_id}/transactions",
        )
        logging.info("TRUV: Link ID - %s", link_id)

        report = self.get(f"links/{link_id}/transactions?page_size=100")

        if report:
            report['transactions'] = report['transactions'][:100]
            for tr in report['transactions']:
                del tr['id']
                del tr['external_id']
                del tr['check_number']
                del tr['location']
                del tr['transacted_at']
                del tr['merchant_category_code']
                del tr['memo']
        return report

    def create_refresh_task(self, access_token: str) -> dict:
        logging.info(
            "TRUV: Requesting a data refresh from https://prod.truv.com/v1/refresh/tasks"
        )
        logging.info("TRUV: Access Token - %s", access_token)

        return self.post(
            "refresh/tasks/",
            json={
                "access_token": access_token,
            },
        )

    def get_refresh_task(self, task_id: str) -> dict:
        logging.info(
            "TRUV: Requesting a refresh task from https://prod.truv.com/v1/refresh/tasks/{task_id}"
        )
        logging.info("TRUV: Task ID - %s", task_id)

        return self.get(f"refresh/tasks/{task_id}/")
