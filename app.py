import os
import sqlite3
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session, flash, g
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "change-this-development-secret")
DB_PATH = os.path.join(os.path.dirname(__file__), "marketplace.db")

def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db

@app.teardown_appcontext
def close_db(_error):
    db = g.pop("db", None)
    if db is not None:
        db.close()

def init_db():
    db = sqlite3.connect(DB_PATH)
    db.execute("PRAGMA foreign_keys = ON")
    db.executescript("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        email TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL CHECK(role IN ('customer','seller','admin')),
        seller_approved INTEGER NOT NULL DEFAULT 0
    );
    CREATE TABLE IF NOT EXISTS products (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        seller_id INTEGER NOT NULL,
        name TEXT NOT NULL,
        description TEXT NOT NULL DEFAULT '',
        price REAL NOT NULL CHECK(price >= 0),
        stock INTEGER NOT NULL DEFAULT 0 CHECK(stock >= 0),
        image_url TEXT NOT NULL DEFAULT '',
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(seller_id) REFERENCES users(id)
    );
    CREATE TABLE IF NOT EXISTS orders (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        customer_id INTEGER NOT NULL,
        total REAL NOT NULL,
        status TEXT NOT NULL DEFAULT 'Placed',
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(customer_id) REFERENCES users(id)
    );
    CREATE TABLE IF NOT EXISTS order_items (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        order_id INTEGER NOT NULL,
        product_id INTEGER NOT NULL,
        seller_id INTEGER NOT NULL,
        quantity INTEGER NOT NULL,
        unit_price REAL NOT NULL,
        FOREIGN KEY(order_id) REFERENCES orders(id),
        FOREIGN KEY(product_id) REFERENCES products(id),
        FOREIGN KEY(seller_id) REFERENCES users(id)
    );
    """)
    admin = db.execute("SELECT id FROM users WHERE email=?", ("admin@market.local",)).fetchone()
    if not admin:
        db.execute("INSERT INTO users(name,email,password_hash,role,seller_approved) VALUES(?,?,?,?,?)",
                   ("Marketplace Admin", "admin@market.local",
                    generate_password_hash("Admin@123"), "admin", 1))
    db.commit()
    db.close()

def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("user_id"):
            flash("Please log in first.", "error")
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped

def role_required(*roles):
    def decorator(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            if not session.get("user_id"):
                flash("Please log in first.", "error")
                return redirect(url_for("login"))

            if session.get("role") not in roles:
                flash("You do not have permission to open that page.", "error")
                return redirect(url_for("index"))

            return view(*args, **kwargs)

        return wrapped
    return decorator

@app.context_processor
def inject_user():
    return {"current_user": session.get("name"), "current_role": session.get("role")}

@app.route("/")
def index():
    db = get_db()
    q = request.args.get("q", "").strip()
    if q:
        products = db.execute("""
            SELECT p.*, u.name AS seller_name FROM products p
            JOIN users u ON u.id=p.seller_id
            WHERE p.name LIKE ? OR p.description LIKE ?
            ORDER BY p.created_at DESC
        """, (f"%{q}%", f"%{q}%")).fetchall()
    else:
        products = db.execute("""
            SELECT p.*, u.name AS seller_name FROM products p
            JOIN users u ON u.id=p.seller_id
            ORDER BY p.created_at DESC
        """).fetchall()
    return render_template("index.html", products=products, q=q)

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        role = request.form.get("role", "customer")
        if not name or not email or len(password) < 8 or role not in ("customer", "seller"):
            flash("Enter all details. Password must be at least 8 characters.", "error")
            return render_template("register.html")
        db = get_db()
        try:
            approved = 0 if role == "seller" else 1
            db.execute("INSERT INTO users(name,email,password_hash,role,seller_approved) VALUES(?,?,?,?,?)",
                       (name, email, generate_password_hash(password), role, approved))
            db.commit()
            flash("Account created. Seller accounts need admin approval before listing products." if role == "seller" else "Account created. Please log in.", "success")
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            flash("That email address is already registered.", "error")
    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        user = get_db().execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
        if user and check_password_hash(user["password_hash"], password):
            session.clear()
            session["user_id"] = user["id"]
            session["name"] = user["name"]
            session["role"] = user["role"]
            session["seller_approved"] = user["seller_approved"]
            flash("Welcome back, " + user["name"] + "!", "success")
            return redirect(url_for("dashboard"))
        flash("Incorrect email or password.", "error")
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for("index"))

@app.route("/dashboard")
@login_required
def dashboard():
    role = session["role"]
    if role == "seller":
        if not session.get("seller_approved"):
            return render_template("pending_seller.html")
        return redirect(url_for("seller_dashboard"))
    if role == "admin":
        return redirect(url_for("admin_dashboard"))
    return redirect(url_for("my_orders"))

@app.route("/seller")
@role_required("seller")
def seller_dashboard():
    if not session.get("seller_approved"):
        return render_template("pending_seller.html")
    db = get_db()
    products = db.execute("SELECT * FROM products WHERE seller_id=? ORDER BY id DESC",
                          (session["user_id"],)).fetchall()
    orders = db.execute("""
        SELECT oi.*, o.id AS order_number, o.status, o.created_at,
               p.name AS product_name, u.name AS customer_name
        FROM order_items oi JOIN orders o ON o.id=oi.order_id
        JOIN products p ON p.id=oi.product_id
        JOIN users u ON u.id=o.customer_id
        WHERE oi.seller_id=? ORDER BY o.id DESC
    """, (session["user_id"],)).fetchall()
    return render_template("seller.html", products=products, orders=orders)

@app.route("/seller/products/new", methods=["GET", "POST"])
@role_required("seller")
def new_product():
    if not session.get("seller_approved"):
        flash("Your seller account is awaiting admin approval.", "error")
        return redirect(url_for("dashboard"))
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        description = request.form.get("description", "").strip()
        image_url = request.form.get("image_url", "").strip()
        try:
            price = float(request.form.get("price", ""))
            stock = int(request.form.get("stock", ""))
            if price < 0 or stock < 0:
                raise ValueError
        except ValueError:
            flash("Price and stock must be valid non-negative numbers.", "error")
            return render_template("product_form.html", product=None)
        if not name:
            flash("Product name is required.", "error")
            return render_template("product_form.html", product=None)
        db = get_db()
        db.execute("INSERT INTO products(seller_id,name,description,price,stock,image_url) VALUES(?,?,?,?,?,?)",
                   (session["user_id"], name, description, price, stock, image_url))
        db.commit()
        flash("Product added successfully.", "success")
        return redirect(url_for("seller_dashboard"))
    return render_template("product_form.html", product=None)

@app.route("/seller/products/<int:product_id>/edit", methods=["GET", "POST"])
@role_required("seller")
def edit_product(product_id):
    db = get_db()
    product = db.execute("SELECT * FROM products WHERE id=? AND seller_id=?",
                          (product_id, session["user_id"])).fetchone()
    if not product:
        flash("Product not found.", "error")
        return redirect(url_for("seller_dashboard"))
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        description = request.form.get("description", "").strip()
        image_url = request.form.get("image_url", "").strip()
        try:
            price = float(request.form.get("price", ""))
            stock = int(request.form.get("stock", ""))
            if price < 0 or stock < 0 or not name:
                raise ValueError
        except ValueError:
            flash("Enter a product name, a valid price, and valid stock.", "error")
            return render_template("product_form.html", product=product)
        db.execute("""UPDATE products SET name=?,description=?,price=?,stock=?,image_url=?
                      WHERE id=? AND seller_id=?""",
                   (name, description, price, stock, image_url, product_id, session["user_id"]))
        db.commit()
        flash("Product updated.", "success")
        return redirect(url_for("seller_dashboard"))
    return render_template("product_form.html", product=product)

@app.route("/seller/products/<int:product_id>/delete", methods=["POST"])
@role_required("seller")
def delete_product(product_id):
    db = get_db()
    product = db.execute("SELECT id FROM products WHERE id=? AND seller_id=?",
                          (product_id, session["user_id"])).fetchone()
    if product:
        # Keep products referenced by past orders to preserve order history.
        used = db.execute("SELECT id FROM order_items WHERE product_id=? LIMIT 1", (product_id,)).fetchone()
        if used:
            flash("This product is in an order history, so it cannot be deleted. Set its stock to 0 instead.", "error")
        else:
            db.execute("DELETE FROM products WHERE id=? AND seller_id=?", (product_id, session["user_id"]))
            db.commit()
            flash("Product deleted.", "success")
    return redirect(url_for("seller_dashboard"))

@app.route("/cart")
def cart():
    cart_items = session.get("cart", {})
    products = []
    total = 0
    db = get_db()
    for pid, qty in cart_items.items():
        p = db.execute("""SELECT p.*, u.name AS seller_name FROM products p
                          JOIN users u ON u.id=p.seller_id WHERE p.id=?""", (int(pid),)).fetchone()
        if p and int(qty) > 0:
            line_total = p["price"] * int(qty)
            products.append({"product": p, "quantity": int(qty), "line_total": line_total})
            total += line_total
    return render_template("cart.html", items=products, total=total)

@app.route("/cart/add/<int:product_id>", methods=["POST"])
def add_to_cart(product_id):
    db = get_db()
    product = db.execute("SELECT * FROM products WHERE id=?", (product_id,)).fetchone()
    if not product:
        flash("Product not found.", "error")
        return redirect(url_for("index"))
    if product["stock"] < 1:
        flash("This product is out of stock.", "error")
        return redirect(url_for("index"))
    cart_items = session.get("cart", {})
    key = str(product_id)
    current_qty = int(cart_items.get(key, 0))
    if current_qty >= product["stock"]:
        flash("You have reached the available stock for this product.", "error")
    else:
        cart_items[key] = current_qty + 1
        session["cart"] = cart_items
        flash("Product added to cart.", "success")
    return redirect(request.referrer or url_for("index"))

@app.route("/cart/update", methods=["POST"])
def update_cart():
    cart_items = session.get("cart", {})
    db = get_db()
    updated = {}
    for key, value in request.form.items():
        if not key.startswith("qty_"):
            continue
        pid = key[4:]
        try:
            qty = int(value)
        except ValueError:
            qty = 0
        product = db.execute("SELECT stock FROM products WHERE id=?", (int(pid),)).fetchone()
        if product and qty > 0:
            updated[pid] = min(qty, product["stock"])
    session["cart"] = updated
    flash("Cart updated.", "success")
    return redirect(url_for("cart"))

@app.route("/checkout", methods=["POST"])
@role_required("customer")
def checkout():
    cart_items = session.get("cart", {})
    if not cart_items:
        flash("Your cart is empty.", "error")
        return redirect(url_for("cart"))
    db = get_db()
    lines = []
    total = 0
    for pid, qty in cart_items.items():
        product = db.execute("SELECT * FROM products WHERE id=?", (int(pid),)).fetchone()
        qty = int(qty)
        if not product or qty < 1 or qty > product["stock"]:
            flash("A product is unavailable or stock changed. Please review your cart.", "error")
            return redirect(url_for("cart"))
        lines.append((product, qty))
        total += product["price"] * qty
    try:
        db.execute("BEGIN")
        cur = db.execute("INSERT INTO orders(customer_id,total,status) VALUES(?,?,?)",
                         (session["user_id"], total, "Placed"))
        order_id = cur.lastrowid
        for product, qty in lines:
            db.execute("INSERT INTO order_items(order_id,product_id,seller_id,quantity,unit_price) VALUES(?,?,?,?,?)",
                       (order_id, product["id"], product["seller_id"], qty, product["price"]))
            db.execute("UPDATE products SET stock=stock-? WHERE id=? AND stock>=?",
                       (qty, product["id"], qty))
            if db.execute("SELECT changes()").fetchone()[0] != 1:
                raise ValueError("Stock changed during checkout.")
        db.commit()
    except Exception:
        db.rollback()
        flash("Checkout could not be completed. Please check stock and try again.", "error")
        return redirect(url_for("cart"))
    session["cart"] = {}
    flash(f"Order #{order_id} placed successfully. This demo does not collect real payments.", "success")
    return redirect(url_for("my_orders"))

@app.route("/orders")
@role_required("customer")
def my_orders():
    db = get_db()
    orders = db.execute("SELECT * FROM orders WHERE customer_id=? ORDER BY id DESC",
                        (session["user_id"],)).fetchall()
    items = {}
    for order in orders:
        items[order["id"]] = db.execute("""
            SELECT oi.*, p.name AS product_name, u.name AS seller_name
            FROM order_items oi JOIN products p ON p.id=oi.product_id
            JOIN users u ON u.id=oi.seller_id WHERE oi.order_id=?
        """, (order["id"],)).fetchall()
    return render_template("orders.html", orders=orders, items=items)

@app.route("/admin")
@role_required("admin")
def admin_dashboard():
    db = get_db()
    sellers = db.execute("SELECT id,name,email,seller_approved FROM users WHERE role='seller' ORDER BY id DESC").fetchall()
    products = db.execute("""
        SELECT p.*, u.name AS seller_name FROM products p
        JOIN users u ON u.id=p.seller_id ORDER BY p.id DESC
    """).fetchall()
    orders = db.execute("""
        SELECT o.*, u.name AS customer_name FROM orders o
        JOIN users u ON u.id=o.customer_id ORDER BY o.id DESC
    """).fetchall()
    return render_template("admin.html", sellers=sellers, products=products, orders=orders)

@app.route("/admin/sellers/<int:seller_id>/approve", methods=["POST"])
@role_required("admin")
def approve_seller(seller_id):
    db = get_db()
    db.execute("UPDATE users SET seller_approved=1 WHERE id=? AND role='seller'", (seller_id,))
    db.commit()
    flash("Seller approval updated.", "success")
    return redirect(url_for("admin_dashboard"))

@app.route("/admin/orders/<int:order_id>/status", methods=["POST"])
@role_required("admin")
def update_order_status(order_id):
    status = request.form.get("status", "")
    allowed = {"Placed", "Processing", "Shipped", "Delivered", "Cancelled"}
    if status not in allowed:
        flash("Invalid order status.", "error")
    else:
        db = get_db()
        db.execute("UPDATE orders SET status=? WHERE id=?", (status, order_id))
        db.commit()
        flash("Order status updated.", "success")
    return redirect(url_for("admin_dashboard"))

@app.errorhandler(404)
def not_found(_error):
    return render_template("404.html"), 404

if __name__ == "__main__":
    init_db()
    app.run(debug=True)
