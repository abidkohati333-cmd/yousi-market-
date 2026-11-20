YOUSI MARKET - Mobile Flask starter

TERMUX SETUP:
1. Install Python in Termux if needed:
   pkg update -y && pkg install python -y
2. Extract this ZIP, then open the extracted folder in Termux.
3. Run:
   pip install -r requirements.txt
   python app.py
4. Open Chrome and visit:
   http://127.0.0.1:5000

This is a starter marketplace: accounts, product listings, search, seller dashboard, and email enquiries.
It does NOT yet include payment processing, shipping, refunds, identity verification, moderation, or a real commission collection system.
Do not collect customer payments or publish publicly until those systems, HTTPS, backups, privacy terms, and secure SECRET_KEY are configured.
