[My project work using Python and Flask]
# GOAL
**Build an anti-spam, double opt-in Email form with Python**

**For the mitigation of email spam, bots and form submission attacks, we use a double opt-in email form.**
## Problem:
A single opt-in form just allows anybody including bots to enter an email address and submit it on your website. Without additional protection like "captcha" or cloudflare, your web app will receive invalid submissions that will waste your system resources. If you're running a cronjob to send out periodic emails, your server will attempt to message the invalid email addresses resulting in errors.

## Solution
We can include a double opt-in form which requires the submitter to confirm their email address upon receipt to their mailbox. This can be in addition to a more technical approach using cloudflare or "captca".

### Our modules consiste of the following.
-Common Python modules for web forms including using templates, a redirect and notification flash
`from flask import Flask, render_template, request, url_for, redirect, flash`
\n
-For mailing messages
`from flask_mail import Mail, Message`
\n
-To include a timestamp when saving to a database
`from datetime import datetime`

from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.sql import func
import secrets
import bleach
import requests
```
