import os, re, sqlite3, secrets, hashlib, hmac, time, json
from datetime import datetime, timezone
from functools import wraps
from flask import Flask, request, session, redirect, url_for, render_template_string, flash, abort, g
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

APP_DIR = os.path.abspath(os.path.dirname(__file__))
DB_PATH = os.path.join(APP_DIR, "yousi_market_secure.db")
SECRET_FILE = os.path.join(APP_DIR, ".yousi_secret")
UPLOAD_DIR = os.path.join(APP_DIR, "static", "uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)

def load_secret():
    env = os.environ.get("YOUSI_SECRET_KEY")
    if env:
        return env
    if os.path.exists(SECRET_FILE):
        return open(SECRET_FILE, "r", encoding="utf-8").read().strip()
    value = secrets.token_urlsafe(48)
    with open(SECRET_FILE, "w", encoding="utf-8") as f:
        f.write(value)
    try: os.chmod(SECRET_FILE, 0o600)
    except OSError: pass
    return value

app = Flask(__name__)
app.secret_key = load_secret()
app.config.update(
    MAX_CONTENT_LENGTH=5 * 1024 * 1024,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "0") == "1",
    PERMANENT_SESSION_LIFETIME=60 * 60 * 8
)

def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys=ON")
        g.db.execute("PRAGMA journal_mode=WAL")
    return g.db

@app.teardown_appcontext
def close_db(_=None):
    conn = g.pop("db", None)
    if conn: conn.close()

def init_db():
    con = sqlite3.connect(DB_PATH)
    con.execute("PRAGMA foreign_keys=ON")
    con.executescript("""
    CREATE TABLE IF NOT EXISTS users(
      id INTEGER PRIMARY KEY, name TEXT NOT NULL, email TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'buyer',
      created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS products(
      id INTEGER PRIMARY KEY, seller_id INTEGER NOT NULL REFERENCES users(id),
      title TEXT NOT NULL, description TEXT NOT NULL DEFAULT '',
      category TEXT NOT NULL, price REAL NOT NULL CHECK(price>=0),
      stock INTEGER NOT NULL DEFAULT 0 CHECK(stock>=0), image TEXT NOT NULL DEFAULT '',
      approved INTEGER NOT NULL DEFAULT 0, active INTEGER NOT NULL DEFAULT 1,
      created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS orders(
      id INTEGER PRIMARY KEY, buyer_id INTEGER NOT NULL REFERENCES users(id),
      customer_name TEXT NOT NULL, phone TEXT NOT NULL, address TEXT NOT NULL,
      total REAL NOT NULL, commission REAL NOT NULL, status TEXT NOT NULL DEFAULT 'New',
      payment_status TEXT NOT NULL DEFAULT 'Unpaid (demo)', created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS order_items(
      id INTEGER PRIMARY KEY, order_id INTEGER NOT NULL REFERENCES orders(id) ON DELETE CASCADE,
      product_id INTEGER NOT NULL REFERENCES products(id), seller_id INTEGER NOT NULL REFERENCES users(id),
      title TEXT NOT NULL, price REAL NOT NULL, quantity INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS carts(
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      product_id INTEGER NOT NULL REFERENCES products(id) ON DELETE CASCADE,
      quantity INTEGER NOT NULL DEFAULT 1, PRIMARY KEY(user_id, product_id)
    );
    CREATE TABLE IF NOT EXISTS wishlists(
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      product_id INTEGER NOT NULL REFERENCES products(id) ON DELETE CASCADE,
      PRIMARY KEY(user_id, product_id)
    );
    """)
    con.commit()
    con.close()

init_db()

# First administrator setup is protected by a one-time token printed in Termux.
def get_setup_token():
    path = os.path.join(APP_DIR, ".yousi_setup_token")
    if os.path.exists(path):
        return open(path, "r", encoding="utf-8").read().strip()
    token = secrets.token_urlsafe(8)
    with open(path, "w", encoding="utf-8") as f: f.write(token)
    try: os.chmod(path, 0o600)
    except OSError: pass
    print("\n[YOUSI MARKET] First-run admin setup code:", token, "\n")
    return token

SETUP_TOKEN = get_setup_token()

def admin_exists():
    return db().execute("SELECT 1 FROM users WHERE role='admin' LIMIT 1").fetchone() is not None

@app.before_request
def security_headers():
    # Session-based CSRF protection for every state-changing form.
    if "csrf" not in session:
        session["csrf"] = secrets.token_urlsafe(24)
    if request.method == "POST":
        sent = request.form.get("csrf", "")
        if not sent or not hmac.compare_digest(sent, session.get("csrf", "")):
            abort(400, "Security check failed. Refresh and try again.")
    # Lightweight per-IP login throttle, kept in process memory.
    if request.endpoint == "login" and request.method == "POST":
        ip = request.remote_addr or "unknown"
        now = time.time()
        bucket = LOGIN_TRIES.setdefault(ip, [])
        bucket[:] = [t for t in bucket if now - t < 600]
        if len(bucket) >= 8:
            abort(429, "Too many login attempts. Please wait 10 minutes.")
        bucket.append(now)

@app.after_request
def add_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Content-Security-Policy"] = "default-src 'self' https: data:; img-src 'self' https: data:; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; script-src 'self' 'unsafe-inline'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'"
    if request.is_secure:
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response

LOGIN_TRIES = {}

def current_user():
    uid = session.get("uid")
    return db().execute("SELECT id,name,email,role FROM users WHERE id=?", (uid,)).fetchone() if uid else None

def login_required(fn):
    @wraps(fn)
    def wrapped(*a, **kw):
        if not current_user():
            flash("Please sign in first.", "warn")
            return redirect(url_for("login"))
        return fn(*a, **kw)
    return wrapped

def role_required(role):
    def deco(fn):
        @wraps(fn)
        def wrapped(*a, **kw):
            u = current_user()
            if not u: return redirect(url_for("login"))
            if u["role"] != role: abort(403)
            return fn(*a, **kw)
        return wrapped
    return deco

def money(v): return "Rs. {:,.0f}".format(float(v or 0))
app.jinja_env.filters["money"] = money

BASE = r"""
<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{{ title }} | YOUSI MARKET</title><meta name="description" content="Discover quality products at YOUSI MARKET.">
<style>
:root{--navy:#131921;--navy2:#232f3e;--gold:#febd69;--ink:#17212b;--muted:#667085;--bg:#f3f5f7;--line:#e5e7eb}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:15px Arial,sans-serif}a{color:inherit;text-decoration:none}
.top{background:var(--navy);color:white;padding:12px max(14px,calc((100% - 1180px)/2));display:flex;align-items:center;gap:16px;flex-wrap:wrap}
.logo{font-size:25px;font-weight:900;letter-spacing:-1px}.logo span{color:var(--gold)}.search{display:flex;flex:1;min-width:210px}.search input{flex:1;min-width:0;padding:12px;border:0;border-radius:6px 0 0 6px}.search button{border:0;background:var(--gold);padding:0 18px;border-radius:0 6px 6px 0;font-weight:bold}
.nav{background:var(--navy2);color:white;padding:10px max(14px,calc((100% - 1180px)/2));display:flex;gap:18px;flex-wrap:wrap;font-size:14px}
.wrap{max-width:1180px;margin:22px auto;padding:0 14px}.hero{background:linear-gradient(115deg,#182b49,#365b7b);color:white;border-radius:15px;padding:34px 28px;margin-bottom:22px;box-shadow:0 8px 24px #14283a20}.hero h1{font-size:clamp(26px,5vw,42px);margin:0 0 10px}.hero p{color:#e7edf4;max-width:620px;line-height:1.6}.btn{display:inline-block;background:var(--gold);color:#17212b;border:0;border-radius:7px;padding:10px 15px;font-weight:700;cursor:pointer}.btn.dark{background:var(--navy2);color:white}.btn.red{background:#b42318;color:white}.btn.light{background:white;border:1px solid var(--line)}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(190px,1fr));gap:16px}.product,.panel{background:white;border:1px solid var(--line);border-radius:12px;padding:14px;box-shadow:0 3px 12px #11100008}.product img{width:100%;height:165px;object-fit:contain;background:#f8fafc;border-radius:8px}.product h3{font-size:16px;line-height:1.35;min-height:42px}.price{font-size:20px;font-weight:800;color:#b12704}.muted{color:var(--muted);font-size:13px}.row{display:flex;align-items:center;justify-content:space-between;gap:10px;flex-wrap:wrap}.section{margin:22px 0 12px}.section h2{font-size:23px;margin:0}.form{max-width:560px;background:white;padding:20px;border-radius:12px;border:1px solid var(--line)}label{display:block;font-weight:700;margin:12px 0 6px}input,textarea,select{width:100%;padding:11px;border:1px solid #cbd5e1;border-radius:7px;font:inherit}textarea{min-height:100px}form .btn{margin-top:14px}.flash{padding:11px 14px;border-radius:8px;background:#e8f4ff;margin:10px 0}.warn{background:#fff2d9}.danger{color:#b42318}.tablewrap{overflow:auto;background:white;border-radius:10px;border:1px solid var(--line)}table{width:100%;border-collapse:collapse;min-width:600px}td,th{text-align:left;padding:12px;border-bottom:1px solid var(--line)}th{background:#f8fafc}.pill{font-size:12px;background:#eef2f6;padding:5px 8px;border-radius:30px}.footer{background:var(--navy2);color:#d8e0e8;text-align:center;padding:28px;margin-top:40px}.cols{display:grid;grid-template-columns:2fr 1fr;gap:18px}.detail{display:grid;grid-template-columns:1fr 1fr;gap:24px}.detail img{width:100%;max-height:420px;object-fit:contain;background:white;border-radius:12px;padding:20px}
@media(max-width:650px){.top{gap:10px}.logo{width:100%}.cols,.detail{grid-template-columns:1fr}.hero{padding:25px 20px}.grid{grid-template-columns:repeat(2,minmax(0,1fr))}.product{padding:10px}.product img{height:125px}.nav{gap:12px}}
</style></head><body>
<header class="top"><a class="logo" href="{{ url_for('home') }}">YOUSI<span> MARKET</span></a>
<form class="search" action="{{ url_for('home') }}" method="get"><input name="q" value="{{ request.args.get('q','') }}" placeholder="Search products, brands and more"><button>Search</button></form>
<a href="{{ url_for('cart') }}">Cart 🛒</a>{% if user %}<a href="{{ url_for('account') }}">Hi, {{ user.name }}</a><a href="{{ url_for('logout') }}">Sign out</a>{% else %}<a href="{{ url_for('login') }}">Sign in</a>{% endif %}</header>
<nav class="nav"><a href="{{ url_for('home') }}">All</a><a href="{{ url_for('home',category='Electronics') }}">Electronics</a><a href="{{ url_for('home',category='Fashion') }}">Fashion</a><a href="{{ url_for('home',category='Home') }}">Home</a><a href="{{ url_for('home',category='Beauty') }}">Beauty</a><a href="{{ url_for('home',category='Sports') }}">Sports</a><a href="{{ url_for('seller') }}">Sell on YOUSI</a>{% if user and user.role=='admin' %}<a href="{{ url_for('admin') }}">Admin</a>{% endif %}</nav>
<main class="wrap">{% for cat,msg in get_flashed_messages(with_categories=true) %}<div class="flash {{ cat }}">{{ msg }}</div>{% endfor %}{{ body|safe }}</main>
<footer class="footer">YOUSI MARKET · Discover more. Shop smarter.<br><small>Demo marketplace. Secure payments are not enabled yet.</small></footer></body></html>
"""

def page(title, body, **context):
    return render_template_string(BASE, title=title, body=render_template_string(body, **context),
                                   user=current_user(), request=request)

HOME = r"""
<section class="hero"><h1>Find something you'll love.</h1><p>Explore hand-picked products across everyday essentials, technology, fashion and home. A better way to discover great finds.</p><a class="btn" href="#products">Explore products</a></section>
<div class="row section"><h2 id="products">Discover products</h2><span class="muted">{{ products|length }} items</span></div>
<div class="grid">{% for p in products %}<article class="product"><a href="{{ url_for('product',pid=p.id) }}"><img src="{{ p.image or 'https://placehold.co/500x400?text=YOUSI+MARKET' }}" alt="Product image"><h3>{{ p.title }}</h3></a><div class="price">{{ p.price|money }}</div><p class="muted">{{ p.category }} · {{ p.stock }} available</p><a class="btn" href="{{ url_for('product',pid=p.id) }}">View details</a></article>{% else %}<div class="panel">No products yet. Sellers can add products after creating an account.</div>{% endfor %}</div>
"""

@app.route("/")
def home():
    q = request.args.get("q","").strip()[:80]
    category = request.args.get("category","").strip()[:40]
    sql = "SELECT * FROM products WHERE approved=1 AND active=1"
    args = []
    if q: sql += " AND (title LIKE ? OR description LIKE ? OR category LIKE ?)"; args += [f"%{q}%"]*3
    if category: sql += " AND category=?"; args.append(category)
    products = db().execute(sql+" ORDER BY id DESC LIMIT 60", args).fetchall()
    return page("Home", HOME, products=products)

@app.route("/setup", methods=["GET","POST"])
def setup():
    if admin_exists(): abort(404)
    if request.method == "POST":
        token = request.form.get("token","")
        name = request.form.get("name","").strip()[:60]
        email = request.form.get("email","").strip().lower()[:120]
        pw = request.form.get("password","")
        if not hmac.compare_digest(token, SETUP_TOKEN): flash("Incorrect setup code.","warn")
        elif not name or not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+",email): flash("Enter a valid name and email.","warn")
        elif len(pw) < 12: flash("Use a password with at least 12 characters.","warn")
        else:
            try:
                db().execute("INSERT INTO users(name,email,password,role,created_at) VALUES(?,?,?,?,?)",
                    (name,email,generate_password_hash(pw), "admin", datetime.now(timezone.utc).isoformat()))
                db().commit()
                try: os.remove(os.path.join(APP_DIR,".yousi_setup_token"))
                except OSError: pass
                session.clear(); flash("Admin account created. Please sign in.")
                return redirect(url_for("login"))
            except sqlite3.IntegrityError: flash("That email is already registered.","warn")
    body = r"""<h2>Secure first-time setup</h2><p class="muted">Read the one-time setup code shown in Termux. Create a strong password and keep it private.</p><form class="form" method="post"><input type="hidden" name="csrf" value="{{ session.csrf }}"><label>One-time setup code</label><input name="token" required><label>Your name</label><input name="name" required><label>Email</label><input name="email" type="email" required><label>Password (12+ characters)</label><input name="password" type="password" minlength="12" required><button class="btn">Create owner account</button></form>"""
    return page("Admin setup",body)

@app.route("/register", methods=["GET","POST"])
def register():
    if request.method=="POST":
        name=request.form.get("name","").strip()[:60]; email=request.form.get("email","").strip().lower()[:120]; pw=request.form.get("password","")
        if len(name)<2 or not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+",email) or len(pw)<10:
            flash("Enter a valid name/email and password of at least 10 characters.","warn")
        else:
            try:
                db().execute("INSERT INTO users(name,email,password,role,created_at) VALUES(?,?,?,?,?)",(name,email,generate_password_hash(pw),"buyer",datetime.now(timezone.utc).isoformat())); db().commit()
                flash("Account created. Sign in to continue."); return redirect(url_for("login"))
            except sqlite3.IntegrityError: flash("This email is already registered.","warn")
    body=r"""<h2>Create your account</h2><form class="form" method="post"><input type="hidden" name="csrf" value="{{ session.csrf }}"><label>Name</label><input name="name" required><label>Email</label><input name="email" type="email" required><label>Password (at least 10 characters)</label><input name="password" type="password" minlength="10" required><button class="btn">Create account</button></form><p>Already registered? <a href="{{ url_for('login') }}">Sign in</a></p>"""
    return page("Register",body)

@app.route("/login", methods=["GET","POST"])
def login():
    if request.method=="POST":
        email=request.form.get("email","").strip().lower(); pw=request.form.get("password","")
        u=db().execute("SELECT * FROM users WHERE email=?",(email,)).fetchone()
        if u and check_password_hash(u["password"],pw):
            session.clear(); session["uid"]=u["id"]; session["csrf"]=secrets.token_urlsafe(24); session.permanent=True
            return redirect(url_for("admin" if u["role"]=="admin" else "account"))
        flash("Email or password is incorrect.","warn")
    body=r"""<h2>Welcome back</h2><form class="form" method="post"><input type="hidden" name="csrf" value="{{ session.csrf }}"><label>Email</label><input name="email" type="email" required><label>Password</label><input name="password" type="password" required><button class="btn">Sign in</button></form><p>New here? <a href="{{ url_for('register') }}">Create account</a></p>"""
    return page("Sign in",body)

@app.route("/logout")
def logout():
    session.clear(); return redirect(url_for("home"))

@app.route("/product/<int:pid>")
def product(pid):
    p=db().execute("SELECT p.*,u.name seller FROM products p JOIN users u ON u.id=p.seller_id WHERE p.id=? AND p.approved=1 AND p.active=1",(pid,)).fetchone()
    if not p: abort(404)
    body=r"""<div class="detail"><img src="{{ p.image or 'https://placehold.co/600x500?text=YOUSI' }}"><div><span class="pill">{{ p.category }}</span><h1>{{ p.title }}</h1><div class="price">{{ p.price|money }}</div><p>{{ p.description }}</p><p class="muted">Sold by {{ p.seller }} · {{ p.stock }} in stock</p>{% if p.stock>0 %}<form method="post" action="{{ url_for('add_cart',pid=p.id) }}"><input type="hidden" name="csrf" value="{{ session.csrf }}"><label>Quantity</label><input name="quantity" type="number" value="1" min="1" max="{{ p.stock }}"><button class="btn">Add to cart</button></form><form method="post" action="{{ url_for('wishlist_add',pid=p.id) }}"><input type="hidden" name="csrf" value="{{ session.csrf }}"><button class="btn light">♡ Save to wishlist</button></form>{% else %}<p>Out of stock</p>{% endif %}</div></div>"""
    return page(p["title"],body,p=p)

@app.route("/cart")
@login_required
def cart():
    rows=db().execute("SELECT c.quantity,p.id,p.title,p.price,p.stock,p.image FROM carts c JOIN products p ON p.id=c.product_id WHERE c.user_id=?",(current_user()["id"],)).fetchall()
    total=sum(r["price"]*r["quantity"] for r in rows)
    body=r"""<h2>Your cart</h2>{% if rows %}<div class="tablewrap"><table><tr><th>Item</th><th>Price</th><th>Quantity</th><th>Subtotal</th><th></th></tr>{% for r in rows %}<tr><td>{{ r.title }}</td><td>{{ r.price|money }}</td><td><form method="post" action="{{ url_for('cart_update',pid=r.id) }}"><input type="hidden" name="csrf" value="{{ session.csrf }}"><input name="quantity" type="number" min="1" max="{{ r.stock }}" value="{{ r.quantity }}" style="width:75px"><button class="btn light">Update</button></form></td><td>{{ (r.price*r.quantity)|money }}</td><td><form method="post" action="{{ url_for('cart_remove',pid=r.id) }}"><input type="hidden" name="csrf" value="{{ session.csrf }}"><button class="btn red">Remove</button></form></td></tr>{% endfor %}</table></div><h2>Total: {{ total|money }}</h2><a class="btn" href="{{ url_for('checkout') }}">Continue to checkout</a>{% else %}<p>Your cart is empty.</p><a class="btn" href="{{ url_for('home') }}">Start shopping</a>{% endif %}"""
    return page("Cart",body,rows=rows,total=total)

@app.post("/cart/add/<int:pid>")
@login_required
def add_cart(pid):
    u=current_user(); p=db().execute("SELECT * FROM products WHERE id=? AND approved=1 AND active=1",(pid,)).fetchone()
    if not p: abort(404)
    try: qty=max(1,min(int(request.form.get("quantity","1")),p["stock"]))
    except ValueError: qty=1
    if qty:
        db().execute("INSERT INTO carts(user_id,product_id,quantity) VALUES(?,?,?) ON CONFLICT(user_id,product_id) DO UPDATE SET quantity=MIN(quantity+excluded.quantity,?)",(u["id"],pid,qty,p["stock"])); db().commit()
        flash("Added to cart.")
    return redirect(url_for("cart"))

@app.post("/cart/update/<int:pid>")
@login_required
def cart_update(pid):
    try: qty=max(1,min(int(request.form.get("quantity","1")),999))
    except ValueError: qty=1
    db().execute("UPDATE carts SET quantity=? WHERE user_id=? AND product_id=?",(qty,current_user()["id"],pid)); db().commit()
    return redirect(url_for("cart"))

@app.post("/cart/remove/<int:pid>")
@login_required
def cart_remove(pid):
    db().execute("DELETE FROM carts WHERE user_id=? AND product_id=?",(current_user()["id"],pid)); db().commit(); return redirect(url_for("cart"))

@app.route("/checkout",methods=["GET","POST"])
@login_required
def checkout():
    u=current_user()
    rows=db().execute("SELECT c.quantity,p.id,p.title,p.price,p.stock,p.seller_id FROM carts c JOIN products p ON p.id=c.product_id WHERE c.user_id=? AND p.approved=1 AND p.active=1",(u["id"],)).fetchall()
    if not rows: return redirect(url_for("cart"))
    total=sum(r["price"]*r["quantity"] for r in rows)
    if request.method=="POST":
        name=request.form.get("name","").strip()[:80]
        phone=request.form.get("phone","").strip()[:30]
        address=request.form.get("address","").strip()[:400]
        payment_method=request.form.get("payment_method","cod")
        if payment_method not in ("cod","demo"):
            payment_method="cod"
        if len(name)<2 or len(phone)<7 or len(address)<8: flash("Please enter complete delivery details.","warn")
        elif any(r["quantity"]>r["stock"] for r in rows): flash("A product is no longer available in that quantity. Update your cart.","warn")
        else:
            commission=round(total*0.05,2)
            payment_label="Cash on Delivery" if payment_method=="cod" else "Unpaid (demo)"
            cur=db().execute("INSERT INTO orders(buyer_id,customer_name,phone,address,total,commission,status,payment_status,created_at) VALUES(?,?,?,?,?,?,?,?,?)",(u["id"],name,phone,address,total,commission,"New",payment_label,datetime.now(timezone.utc).isoformat()))
            oid=cur.lastrowid
            for r in rows:
                db().execute("INSERT INTO order_items(order_id,product_id,seller_id,title,price,quantity) VALUES(?,?,?,?,?,?)",(oid,r["id"],r["seller_id"],r["title"],r["price"],r["quantity"]))
                db().execute("UPDATE products SET stock=stock-? WHERE id=?",(r["quantity"],r["id"]))
            db().execute("DELETE FROM carts WHERE user_id=?",(u["id"],)); db().commit()
            flash("Your Cash on Delivery order has been placed successfully."); return redirect(url_for("orders"))
    body=r"""<h2>Checkout</h2><div class="cols"><form class="form" method="post"><input type="hidden" name="csrf" value="{{ session.csrf }}"><label>Full name</label><input name="name" required><label>Phone number</label><input name="phone" required><label>Delivery address</label><textarea name="address" required></textarea><label>Payment method</label><select name="payment_method"><option value="cod">Cash on Delivery (pay when delivered)</option><option value="demo">Demo / No payment</option></select><button class="btn">Place order</button></form><div class="panel"><h3>Order total</h3><div class="price">{{ total|money }}</div><p class="muted">This demo checkout does not collect payment. A real payment provider must be connected before public sales.</p></div></div>"""
    return page("Checkout",body,total=total)

@app.route("/orders")
@login_required
def orders():
    rows=db().execute("SELECT * FROM orders WHERE buyer_id=? ORDER BY id DESC",(current_user()["id"],)).fetchall()
    body=r"""<h2>Your orders</h2>{% for o in rows %}<div class="panel" style="margin:12px 0"><div class="row"><b>Order #{{ o.id }}</b><span class="pill">{{ o.status }}</span></div><p>{{ o.total|money }} · {{ o.payment_status }}</p><p class="muted">{{ o.created_at[:19] }}</p></div>{% else %}<p>No orders yet.</p>{% endfor %}"""
    return page("Orders",body,rows=rows)

@app.route("/wishlist")
@login_required
def wishlist():
    rows=db().execute("SELECT p.* FROM wishlists w JOIN products p ON p.id=w.product_id WHERE w.user_id=?",(current_user()["id"],)).fetchall()
    body=r"""<h2>Saved products</h2><div class="grid">{% for p in rows %}<div class="product"><a href="{{ url_for('product',pid=p.id) }}"><img src="{{ p.image }}"><h3>{{ p.title }}</h3></a><b>{{ p.price|money }}</b></div>{% else %}<p>No saved products yet.</p>{% endfor %}</div>"""
    return page("Wishlist",body,rows=rows)

@app.post("/wishlist/add/<int:pid>")
@login_required
def wishlist_add(pid):
    db().execute("INSERT OR IGNORE INTO wishlists(user_id,product_id) VALUES(?,?)",(current_user()["id"],pid)); db().commit(); flash("Saved to wishlist."); return redirect(url_for("wishlist"))

@app.route("/account")
@login_required
def account():
    body=r"""<h2>Your account</h2><div class="grid"><a class="panel" href="{{ url_for('orders') }}"><h3>📦 Your orders</h3><p class="muted">Track your order records</p></a><a class="panel" href="{{ url_for('wishlist') }}"><h3>♡ Wishlist</h3><p class="muted">Your saved items</p></a><a class="panel" href="{{ url_for('seller') }}"><h3>🏪 Seller centre</h3><p class="muted">Start selling on YOUSI</p></a></div>"""
    return page("Account",body)

@app.post("/seller/order/<int:oid>/status")
@login_required
def seller_order_status(oid):
    uid = current_user()["id"]
    status = request.form.get("status", "")
    allowed = ["New", "Processing", "Shipped", "Delivered", "Cancelled"]

    owns = db().execute(
        "SELECT 1 FROM order_items WHERE order_id=? AND seller_id=? LIMIT 1",
        (oid, uid)
    ).fetchone()

    if not owns or status not in allowed:
        flash("Invalid order or status.", "warn")
    else:
        db().execute("UPDATE orders SET status=? WHERE id=?", (status, oid))
        db().commit()
        flash("Order status updated.")

    return redirect(url_for("seller"))


@app.route("/seller",methods=["GET","POST"])
@login_required
def seller():
    u=current_user()
    if u["role"]=="buyer":
        db().execute("UPDATE users SET role='seller' WHERE id=?",(u["id"],))
        db().commit()
    if request.method=="POST":
        title=request.form.get("title","").strip()[:100]
        desc=request.form.get("description","").strip()[:1500]
        cat=request.form.get("category","Other")
        try:
            price=float(request.form.get("price","0"))
            stock=int(request.form.get("stock","0"))
        except ValueError:
            price=-1
            stock=-1
        image=request.form.get("image","").strip()[:500]
        if not title or price<=0 or stock<0:
            flash("Enter a valid title, price and stock.","warn")
        elif image and not (image.startswith("https://") or image.startswith("/static/uploads/")):
            flash("Image must use HTTPS.","warn")
        else:
            db().execute("""INSERT INTO products
            (seller_id,title,description,category,price,stock,image,approved,created_at)
            VALUES(?,?,?,?,?,?,?,?,?)""",
            (u["id"],title,desc,cat,price,stock,image,0,datetime.now(timezone.utc).isoformat()))
            db().commit()
            flash("Product submitted for admin approval.")
        return redirect(url_for("seller"))

    con=db()
    products=con.execute("SELECT * FROM products WHERE seller_id=? ORDER BY id DESC",(u["id"],)).fetchall()
    sales=con.execute("""SELECT o.id order_id,o.customer_name,o.phone,o.address,o.status,
    o.created_at,oi.title,oi.price,oi.quantity
    FROM order_items oi JOIN orders o ON o.id=oi.order_id
    WHERE oi.seller_id=? ORDER BY o.id DESC""",(u["id"],)).fetchall()

    body=r"""<h2>Seller centre</h2>
    <div class="cols">
    <form class="form" method="post">
    <input type="hidden" name="csrf" value="{{ session.csrf }}">
    <h3>Add a product</h3>
    <label>Product name</label><input name="title" required>
    <label>Description</label><textarea name="description"></textarea>
    <label>Category</label><select name="category">{% for c in ['Electronics','Fashion','Home','Beauty','Sports','Books','Other'] %}<option>{{ c }}</option>{% endfor %}</select>
    <label>Price (PKR)</label><input name="price" type="number" min="1" required>
    <label>Stock</label><input name="stock" type="number" min="0" required>
    <label>Image HTTPS link</label><input name="image">
    <button class="btn">Add product</button></form>
    <div><h3>Your products</h3>
    {% for p in products %}
    <div class="panel" style="margin-bottom:10px">
    <b>{{ p.title }}</b><p>{{ p.price|money }} · Stock: {{ p.stock }}</p>
    <p>{{ 'Approved' if p.approved else 'Waiting for approval' }} · {{ 'Active' if p.active else 'Paused' }}</p>
    <a class="btn" href="{{ url_for('seller_edit',pid=p.id) }}">Edit</a>
    <form method="post" action="{{ url_for('seller_toggle',pid=p.id) }}" style="display:inline">
    <input type="hidden" name="csrf" value="{{ session.csrf }}">
    <button class="btn light">{{ 'Pause' if p.active else 'Activate' }}</button></form>
    </div>
    {% else %}<p>No products submitted.</p>{% endfor %}
    </div></div>
    <h2 class="section">Your sales and orders</h2>
    {% for o in sales %}
    <div class="panel" style="margin-bottom:10px">
    <b>Order #{{ o.order_id }} · {{ o.title }}</b>
    <p>Quantity: {{ o.quantity }} · {{ (o.price*o.quantity)|money }}</p>
    <p>Buyer: {{ o.customer_name }} · {{ o.phone }}</p>
    <p>Delivery: {{ o.address }}</p>
    <p>Status: {{ o.status }}</p>
    <form method="post" action="{{ url_for('seller_order_status',oid=o.order_id) }}">
    <input type="hidden" name="csrf" value="{{ session.csrf }}">
    <select name="status">
    {% for st in ['New','Processing','Shipped','Delivered','Cancelled'] %}
    <option value="{{ st }}" {% if o.status == st %}selected{% endif %}>{{ st }}</option>
    {% endfor %}
    </select>
    <button class="btn">Save status</button>
    </form>
    </div>
    {% else %}<p>No sales yet.</p>{% endfor %}"""
    return page("Seller centre",body,products=products,sales=sales)


@app.route("/seller/product/<int:pid>/edit",methods=["GET","POST"])
@login_required
def seller_edit(pid):
    u=current_user()
    p=db().execute("SELECT * FROM products WHERE id=? AND seller_id=?",(pid,u["id"])).fetchone()
    if not p:
        abort(404)
    if request.method=="POST":
        title=request.form.get("title","").strip()[:100]
        desc=request.form.get("description","").strip()[:1500]
        cat=request.form.get("category","Other")
        try:
            price=float(request.form.get("price","0"))
            stock=int(request.form.get("stock","0"))
        except ValueError:
            price=-1
            stock=-1
        image=request.form.get("image","").strip()[:500]
        if not title or price<=0 or stock<0:
            flash("Enter valid product details.","warn")
        elif image and not (image.startswith("https://") or image.startswith("/static/uploads/")):
            flash("Image must use HTTPS.","warn")
        else:
            db().execute("""UPDATE products SET title=?,description=?,category=?,
            price=?,stock=?,image=?,approved=0 WHERE id=? AND seller_id=?""",
            (title,desc,cat,price,stock,image,pid,u["id"]))
            db().commit()
            flash("Product updated. Admin approval is required again.")
            return redirect(url_for("seller"))
    body=r"""<h2>Edit product</h2><form class="form" method="post">
    <input type="hidden" name="csrf" value="{{ session.csrf }}">
    <label>Product name</label><input name="title" value="{{ p.title }}" required>
    <label>Description</label><textarea name="description">{{ p.description }}</textarea>
    <label>Category</label><select name="category">{% for c in ['Electronics','Fashion','Home','Beauty','Sports','Books','Other'] %}<option {{ 'selected' if c==p.category }}>{{ c }}</option>{% endfor %}</select>
    <label>Price (PKR)</label><input name="price" type="number" min="1" value="{{ p.price }}" required>
    <label>Stock</label><input name="stock" type="number" min="0" value="{{ p.stock }}" required>
    <label>Image HTTPS link</label><input name="image" value="{{ p.image }}">
    <button class="btn">Save changes</button></form>"""
    return page("Edit product",body,p=p)


@app.route("/seller/product/<int:pid>/toggle",methods=["POST"])
@login_required
def seller_toggle(pid):
    u=current_user()
    p=db().execute("SELECT active FROM products WHERE id=? AND seller_id=?",(pid,u["id"])).fetchone()
    if not p:
        abort(404)
    db().execute("UPDATE products SET active=? WHERE id=? AND seller_id=?",
                 (0 if p["active"] else 1,pid,u["id"]))
    db().commit()
    return redirect(url_for("seller"))


@app.route("/admin")
@role_required("admin")
def admin():
    con=db()
    products=con.execute("SELECT p.*,u.name seller FROM products p JOIN users u ON u.id=p.seller_id ORDER BY p.id DESC LIMIT 100").fetchall()
    orders=con.execute("SELECT o.*,u.name buyer FROM orders o JOIN users u ON u.id=o.buyer_id ORDER BY o.id DESC LIMIT 100").fetchall()
    users=con.execute("SELECT id,name,email,role,created_at FROM users ORDER BY id DESC LIMIT 100").fetchall()
    body=r"""<h2>Owner control panel</h2><div class="grid"><div class="panel"><h3>{{ users|length }}</h3><p>Recent accounts</p></div><div class="panel"><h3>{{ products|length }}</h3><p>Products</p></div><div class="panel"><h3>{{ orders|length }}</h3><p>Orders</p></div></div><div class="section"><h2>Product moderation</h2></div><div class="tablewrap"><table><tr><th>Product</th><th>Seller</th><th>Price</th><th>Status</th><th>Action</th></tr>{% for p in products %}<tr><td>{{ p.title }}</td><td>{{ p.seller }}</td><td>{{ p.price|money }}</td><td>{{ 'Approved' if p.approved else 'Pending' }}</td><td><form method="post" action="{{ url_for('admin_product',pid=p.id) }}"><input type="hidden" name="csrf" value="{{ session.csrf }}"><button class="btn">{{ 'Hide' if p.approved else 'Approve' }}</button></form></td></tr>{% endfor %}</table></div><div class="section"><h2>Order management</h2></div><div class="tablewrap"><table><tr><th>Order</th><th>Buyer</th><th>Total</th><th>Payment Method</th><th>Commission (5% estimate)</th><th>Status</th><th>Update</th></tr>{% for o in orders %}<tr><td>#{{ o.id }}</td><td>{{ o.buyer }}</td><td>{{ o.total|money }}</td><td>{{ o.payment_status }}</td><td>{{ o.commission|money }}</td><td>{{ o.status }}</td><td><form method="post" action="{{ url_for('admin_order',oid=o.id) }}"><input type="hidden" name="csrf" value="{{ session.csrf }}"><select name="status">{% for s in ['New','Processing','Shipped','Delivered','Cancelled'] %}<option {{ 'selected' if s==o.status }}>{{ s }}</option>{% endfor %}</select><button class="btn light">Save</button></form></td></tr>{% endfor %}</table></div><div class="section"><h2>Accounts</h2></div><div class="tablewrap"><table><tr><th>Name</th><th>Email</th><th>Role</th></tr>{% for u in users %}<tr><td>{{ u.name }}</td><td>{{ u.email }}</td><td>{{ u.role }}</td></tr>{% endfor %}</table></div><p class="muted">Never share your owner password or setup code. Admin panel access is restricted to the owner account.</p>"""
    return page("Admin",body,products=products,orders=orders,users=users)

@app.post("/admin/product/<int:pid>")
@role_required("admin")
def admin_product(pid):
    p=db().execute("SELECT approved FROM products WHERE id=?",(pid,)).fetchone()
    if not p: abort(404)
    db().execute("UPDATE products SET approved=? WHERE id=?",(0 if p["approved"] else 1,pid)); db().commit(); return redirect(url_for("admin"))

@app.post("/admin/order/<int:oid>")
@role_required("admin")
def admin_order(oid):
    status=request.form.get("status","New")
    if status not in ["New","Processing","Shipped","Delivered","Cancelled"]: abort(400)
    db().execute("UPDATE orders SET status=? WHERE id=?",(status,oid)); db().commit(); return redirect(url_for("admin"))

@app.errorhandler(400)
def bad_request(e): return page("Security check",r"""<div class="panel"><h2>Request could not be completed</h2><p>{{ message }}</p><a class="btn" href="{{ url_for('home') }}">Return home</a></div>""",message=getattr(e,"description","Please refresh and try again.")),400
@app.errorhandler(403)
def forbidden(e): return page("Access denied",r"""<div class="panel"><h2>Access denied</h2><p>You do not have permission to view this page.</p></div>"""),403
@app.errorhandler(404)
def not_found(e): return page("Not found",r"""<div class="panel"><h2>Page not found</h2><a class="btn" href="{{ url_for('home') }}">Go home</a></div>"""),404
@app.errorhandler(429)
def too_many(e): return page("Please wait",r"""<div class="panel"><h2>Please wait</h2><p>{{ message }}</p></div>""",message=getattr(e,"description","Try again later.")),429

if __name__ == "__main__":
    print("\nYOUSI MARKET secure edition")
    print("If this is the first launch, open /setup and use the one-time setup code printed above.")
    print("Local test: http://127.0.0.1:5000")
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT","5000")), debug=False)
