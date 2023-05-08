import logging
import json
from typing import Union

import requests
from sendgrid import SendGridAPIClient
from retry.api import retry

import services.aws
import internals

logger = logging.getLogger()

SENDGRID_TEMPLATES = {
    "early_warning_service": "d-4d6ad6a796bb4021a326fb8ca7fb47d2",
    "findings_digest": "d-6b5969c92bd54591bccc72919f5d56b9",
    "invitations": "d-c4a471191062414ea3cefd67c98deed4",
    "magic_link": "d-48aa0ed2e9ff442ea6ee9b73ac984b96",
    "recovery_request": "d-1958843496444e7bb8e29f4277e74182",
    "registrations": "d-a0a115275e404b32bf96b540ecdffeda",
    "scan_completed": "d-b3e18e04202449398bb631694f10753e",
    "subscriptions": "d-1d20f029d4eb46b5957c253c3ccd3262",
    "support": "d-821ef38856bb4d0581f26c4745ce00e7",
    "updated_email": "d-fef742bc0a754165a8778f4929df3dbb",
    "webhook_signing_secret": "d-98a39d14bb11487c94f27d9df88c5c82"
}
SENDGRID_GROUPS = {
    'notifications': 18318,
    'focus_group': 18317,
    'subscriptions': 18319,
    'marketing': 18316,
}
SENDGRID_LISTS = {
    'subscribers': "09998a12-998c-4ca8-990d-2c5e66f0c0ef",
    'members': "ce2b465e-60cd-426c-9ac1-78cdb8e9a4c4",
    'trials': "f0c56ac3-7317-4b39-9a26-b4e37bc33efd",
}

@retry(
    (
        requests.exceptions.JSONDecodeError,
        json.decoder.JSONDecodeError
    ),
    tries=3,
    delay=1.5,
    backoff=1,
)
def _get_pubkey(secret_key: str):
    return requests.get(
        url='https://api.sendgrid.com/v3/user/webhooks/event/settings/signed',
        headers=SendGridAPIClient(secret_key).client.request_headers,
        timeout=(5, 15)
    ).json().get('public_key')

try:
    SENDGRID_API_KEY = services.aws.get_ssm(f'/{internals.APP_ENV}/{internals.APP_NAME}/Sendgrid/api-key', WithDecryption=True)
    WEBHOOK_PUBLIC_KEY = _get_pubkey(SENDGRID_API_KEY)
except Exception as err:
    internals.logger.exception(err)
    exit(1)

def send_email(
    subject: str,
    template: str,
    data: dict,
    recipient: str,
    group: str = 'notifications',
    sender: str = 'support@trivialsec.com',
    sender_name: str = 'Chris @ Trivial Security',
    cc: Union[str, None] = None,
    bcc: Union[str, None] = None,
):
    sendgrid = SendGridAPIClient(SENDGRID_API_KEY)
    tmp_url = sendgrid.client.mail.send._build_url(query_params={})  # pylint: disable=protected-access
    try:
        raw = json.dumps(data, cls=internals.JSONEncoder)
        data = json.loads(raw, parse_float=str, parse_int=str)
    except json.JSONDecodeError as ex:
        internals.logger.error(ex, exc_info=True)
        return False
    personalization = {
        'subject': subject,
        "dynamic_template_data": {**data, **{"email": recipient, "subject": subject}},
        'to': [
            {
                'email': recipient
            }
        ],
    }
    mail_settings = {
        "footer": {
            "enable": False,
        },
        "sandbox_mode": {
            "enable": internals.APP_ENV == "Local"
        }
    }
    if cc is not None and cc != recipient:
        mail_settings['cc'] = {'email': cc, 'enable': True}  # type: ignore
        personalization['cc'] = [
            {
                'email': cc,
                'enable': True
            }
        ]
    if bcc is not None and bcc != recipient:
        mail_settings['bcc'] = {'email': bcc, 'enable': True}  # type: ignore
        personalization['bcc'] = [
            {
                'email': bcc,
                'enable': True
            }
        ]
    req_body = {
        'subject': subject,
        'from': {'email': "donotreply@trivialsec.com", 'name': sender_name},
        'reply_to': {'email': sender},
        'mail_settings': mail_settings,
        'template_id': SENDGRID_TEMPLATES.get(template),
        'asm': {
            'group_id': SENDGRID_GROUPS.get(group)
        },
        'personalizations': [personalization],
    }
    res = requests.post(
        url=tmp_url,
        json=req_body,
        headers=sendgrid.client.request_headers,
        timeout=(5, 15)
    )
    logger.info(res.__dict__)
    if res.headers.get("X-Message-Id"):
        internals.trace_tag({res.headers.get("X-Message-Id"): f'urn:sendgrid:email:{recipient}'})  # type: ignore
    return res


def upsert_contact(recipient_email: str, list_name: str = 'subscribers'):
    sendgrid = SendGridAPIClient(SENDGRID_API_KEY)
    res = requests.put(
        url='https://api.sendgrid.com/v3/marketing/contacts',
        json={
            "list_ids": [
                SENDGRID_LISTS.get(list_name)
            ],
            "contacts": [{
                "email": recipient_email
            }]
        },
        headers=sendgrid.client.request_headers,
        timeout=(5, 15)
    )
    logger.debug(res.__dict__)
    return res


def get_contact(contact_email: str):
    sg = SendGridAPIClient(SENDGRID_API_KEY)
    response = sg.client.marketing.contacts.search.emails.post(
        request_body={"emails": [contact_email]}
    )
    if response.status_code == 200:
        res = json.loads(response.body.decode())  # type: ignore
        return res['result'][contact_email]
