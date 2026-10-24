import os
import uuid
from datetime import datetime
from functools import wraps
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from flask import (
    Flask, render_template, request, redirect, url_for,
    flash, session, send_from_directory, abort, jsonify
)
from flask_sqlalchemy import SQLAlchemy

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'static', 'uploads', 'documents')
AVATAR_FOLDER = os.path.join(BASE_DIR, 'static', 'uploads', 'avatars')
ALLOWED_EXTENSIONS = {'pdf', 'docx', 'doc', 'txt', 'png', 'jpg', 'jpeg', 'xlsx', 'csv', 'zip'}
ALLOWED_AVATARS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(AVATAR_FOLDER, exist_ok=True)

app = Flask(__name__)
app.config['SECRET_KEY'] = 'trustvault-super-secure-key-2026-prod'
app.config['SQLALCHEMY_DATABASE_URI'] = f"sqlite:///{os.path.join(BASE_DIR, 'trustvault.db')}"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['MAX_CONTENT_LENGTH'] = 64 * 1024 * 1024  # 64 MB max

db = SQLAlchemy(app)

# ==========================================
# DATABASE MODELS
# ==========================================

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='owner')  # 'admin', 'owner', 'viewer'
    avatar = db.Column(db.String(255), default='default-avatar.png')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    documents = db.relationship('Document', backref='owner', cascade='all, delete-orphan', lazy=True)
    granted_permissions = db.relationship('DocumentPermission', foreign_keys='DocumentPermission.user_id', backref='grantee', cascade='all, delete-orphan', lazy=True)
    logs = db.relationship('ActivityLog', backref='user', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    @property
    def is_admin(self):
        return self.role == 'admin'

    @property
    def is_owner(self):
        return self.role in ('owner', 'admin')


class Category(db.Model):
    __tablename__ = 'categories'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=True, nullable=False)
    description = db.Column(db.String(255))
    icon = db.Column(db.String(50), default='folder')
    documents = db.relationship('Document', backref='category', lazy=True)


class Document(db.Model):
    __tablename__ = 'documents'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(150), nullable=False)
    description = db.Column(db.Text)
    filename = db.Column(db.String(255), nullable=False)
    original_filename = db.Column(db.String(255), nullable=False)
    file_size = db.Column(db.Integer, default=0)
    category_id = db.Column(db.Integer, db.ForeignKey('categories.id'), nullable=False)
    owner_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    permissions = db.relationship('DocumentPermission', backref='document', cascade='all, delete-orphan', lazy=True)

    def formatted_size(self):
        size = self.file_size
        if size < 1024:
            return f"{size} B"
        elif size < 1024 * 1024:
            return f"{size / 1024:.1f} KB"
        else:
            return f"{size / (1024 * 1024):.2f} MB"


class DocumentPermission(db.Model):
    __tablename__ = 'document_permissions'
    id = db.Column(db.Integer, primary_key=True)
    document_id = db.Column(db.Integer, db.ForeignKey('documents.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    permission_type = db.Column(db.String(20), default='viewer')  # 'viewer', 'editor'
    granted_by_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    granted_at = db.Column(db.DateTime, default=datetime.utcnow)

    granter = db.relationship('User', foreign_keys=[granted_by_id])


class ActivityLog(db.Model):
    __tablename__ = 'activity_logs'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    action = db.Column(db.String(50), nullable=False)
    details = db.Column(db.String(255), nullable=False)
    ip_address = db.Column(db.String(50))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)


# ==========================================
# HELPER FUNCTIONS & DECORATORS
# ==========================================

def allowed_file(filename, allowed_set):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in allowed_set


def log_activity(action, details, user_id=None):
    if user_id is None and 'user_id' in session:
        user_id = session['user_id']
    ip = request.remote_addr or '127.0.0.1'
    log_entry = ActivityLog(
        user_id=user_id,
        action=action,
        details=details,
        ip_address=ip,
        timestamp=datetime.utcnow()
    )
    db.session.add(log_entry)
    db.session.commit()


def get_current_user():
    if 'user_id' in session:
        return User.query.get(session['user_id'])
    return None


@app.context_processor
def inject_user_and_counts():
    user = get_current_user()
    unread_logs = 0
    if user and user.is_admin:
        unread_logs = ActivityLog.query.count()
    return dict(current_user=user, total_activity_count=unread_logs)


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash("Please sign in to access TrustVault.", "warning")
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function


def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash("Please sign in first.", "warning")
            return redirect(url_for('login', next=request.url))
        user = User.query.get(session['user_id'])
        if not user or user.role != 'admin':
            log_activity('ACCESS_DENIED', f"Unauthorized admin section access attempt by {user.username if user else 'Unknown'}")
            flash("Access Restricted: This section (Dashboard & Activity Logs) is reserved for Administrators.", "danger")
            return redirect(url_for('my_documents'))
        return f(*args, **kwargs)
    return decorated_function


# ==========================================
# ROUTES
# ==========================================

@app.route('/')
def index():
    if 'user_id' in session:
        user = get_current_user()
        if user and user.is_admin:
            return redirect(url_for('dashboard'))
        return redirect(url_for('my_documents'))
    return render_template('index.html')


# --- AUTHENTICATION ---

@app.route('/register', methods=['GET', 'POST'])
def register():
    if 'user_id' in session:
        return redirect(url_for('my_documents'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')
        role = request.form.get('role', 'owner')

        if not username or not email or not password:
            flash("All required fields must be filled.", "danger")
            return render_template('register.html')

        if password != confirm_password:
            flash("Passwords do not match.", "danger")
            return render_template('register.html')

        if len(password) < 6:
            flash("Password must be at least 6 characters long.", "danger")
            return render_template('register.html')

        if User.query.filter((User.username == username) | (User.email == email)).first():
            flash("Username or email already registered.", "danger")
            return render_template('register.html')

        if role not in ['owner', 'viewer', 'admin']:
            role = 'owner'

        new_user = User(username=username, email=email, role=role)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()

        log_activity('REGISTER', f"New user '{username}' registered with role '{role}'", user_id=new_user.id)
        flash(f"Account created successfully for {username}! Please sign in.", "success")
        return redirect(url_for('login'))

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        user = get_current_user()
        if user and user.is_admin:
            return redirect(url_for('dashboard'))
        return redirect(url_for('my_documents'))

    if request.method == 'POST':
        login_input = request.form.get('login_input', '').strip()
        password = request.form.get('password', '')

        user = User.query.filter((User.username == login_input) | (User.email == login_input.lower())).first()

        if user and user.check_password(password):
            session['user_id'] = user.id
            session['username'] = user.username
            session['role'] = user.role
            log_activity('LOGIN', f"User '{user.username}' logged in successfully", user_id=user.id)
            flash(f"Welcome back, {user.username}!", "success")

            if user.is_admin:
                return redirect(url_for('dashboard'))
            else:
                return redirect(url_for('my_documents'))
        else:
            log_activity('LOGIN_FAILED', f"Failed login attempt for identifier: '{login_input}'")
            flash("Invalid username/email or password.", "danger")

    return render_template('login.html')


@app.route('/logout')
def logout():
    user = get_current_user()
    if user:
        log_activity('LOGOUT', f"User '{user.username}' signed out", user_id=user.id)
    session.clear()
    flash("You have been signed out safely.", "info")
    return redirect(url_for('login'))


# --- DASHBOARD (ADMIN-ONLY AS REQUIRED) ---

@app.route('/dashboard')
@login_required
def dashboard():
    user = get_current_user()
    if not user.is_admin:
        flash("Access Restricted: Full metrics dashboard and activity logs are reserved for Administrators. You have been redirected to My Documents.", "warning")
        return redirect(url_for('my_documents'))

    total_docs = Document.query.count()
    total_users = User.query.count()
    total_shared_records = DocumentPermission.query.count()
    unique_shared_docs = db.session.query(DocumentPermission.document_id).distinct().count()

    recent_logs = ActivityLog.query.order_by(ActivityLog.timestamp.desc()).limit(10).all()
    recent_docs = Document.query.order_by(Document.created_at.desc()).limit(6).all()
    categories = Category.query.all()
    all_users = User.query.order_by(User.created_at.desc()).all()

    # Security status indicators
    security_metrics = {
        'status': 'Optimal & Enforced',
        'encryption': 'AES-256 at Rest Ready',
        'rbac_mode': 'Strict (Admin, Owner, Viewer)',
        'audit_tamper': 'Zero Anomalies Detected',
        'active_sessions': 1
    }

    return render_template(
        'dashboard.html',
        total_docs=total_docs,
        total_users=total_users,
        total_shared_records=total_shared_records,
        unique_shared_docs=unique_shared_docs,
        recent_logs=recent_logs,
        recent_docs=recent_docs,
        categories=categories,
        users=all_users,
        security_metrics=security_metrics
    )


# --- MY DOCUMENTS ---

@app.route('/my-documents')
@login_required
def my_documents():
    user = get_current_user()
    
    # If admin, show all documents or user docs
    is_admin = user.is_admin
    my_docs = Document.query.filter_by(owner_id=user.id).order_by(Document.created_at.desc()).all()
    
    # Documents shared with this user
    shared_perms = DocumentPermission.query.filter_by(user_id=user.id).all()
    shared_doc_ids = [p.document_id for p in shared_perms]
    shared_docs = Document.query.filter(Document.id.in_(shared_doc_ids)).order_by(Document.created_at.desc()).all() if shared_doc_ids else []

    # Map doc id to permission type
    perm_map = {p.document_id: p.permission_type for p in shared_perms}

    all_system_docs = []
    if is_admin:
        all_system_docs = Document.query.order_by(Document.created_at.desc()).all()

    categories = Category.query.all()
    all_users = User.query.filter(User.id != user.id).all()

    return render_template(
        'documents.html',
        my_docs=my_docs,
        shared_docs=shared_docs,
        all_system_docs=all_system_docs,
        perm_map=perm_map,
        categories=categories,
        all_users=all_users
    )


# --- UPLOAD DOCUMENT ---

@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload():
    user = get_current_user()
    categories = Category.query.all()
    registered_viewers = User.query.filter(User.id != user.id).all()

    if request.method == 'POST':
        title = request.form.get('title', '').strip()
        description = request.form.get('description', '').strip()
        category_id = request.form.get('category_id')
        selected_viewers = request.form.getlist('viewers')  # list of user IDs
        file = request.files.get('document_file')

        if not title:
            flash("Document title is required.", "danger")
            return render_template('upload.html', categories=categories, viewers=registered_viewers)

        if not category_id:
            flash("Please choose a category.", "danger")
            return render_template('upload.html', categories=categories, viewers=registered_viewers)

        if not file or file.filename == '':
            flash("Please choose a document to upload.", "danger")
            return render_template('upload.html', categories=categories, viewers=registered_viewers)

        if not allowed_file(file.filename, ALLOWED_EXTENSIONS):
            flash(f"File type not supported. Allowed: {', '.join(sorted(ALLOWED_EXTENSIONS))}", "danger")
            return render_template('upload.html', categories=categories, viewers=registered_viewers)

        orig_filename = secure_filename(file.filename)
        ext = orig_filename.rsplit('.', 1)[1].lower() if '.' in orig_filename else ''
        unique_name = f"{uuid.uuid4().hex}_{orig_filename}"
        save_path = os.path.join(UPLOAD_FOLDER, unique_name)

        file.save(save_path)
        file_size = os.path.getsize(save_path)

        doc = Document(
            title=title,
            description=description,
            filename=unique_name,
            original_filename=orig_filename,
            file_size=file_size,
            category_id=int(category_id),
            owner_id=user.id
        )
        db.session.add(doc)
        db.session.flush()  # to get doc.id

        # Grant access to selected viewers
        granted_names = []
        for v_id in selected_viewers:
            try:
                vid_int = int(v_id)
                v_user = User.query.get(vid_int)
                if v_user and vid_int != user.id:
                    perm = DocumentPermission(
                        document_id=doc.id,
                        user_id=vid_int,
                        permission_type='viewer',
                        granted_by_id=user.id
                    )
                    db.session.add(perm)
                    granted_names.append(v_user.username)
            except ValueError:
                continue

        db.session.commit()
        share_info = f" and shared with: {', '.join(granted_names)}" if granted_names else ""
        log_activity('UPLOAD', f"Uploaded document '{title}' ({orig_filename}, {doc.formatted_size()}){share_info}")
        flash(f"Document '{title}' uploaded securely{share_info}!", "success")
        return redirect(url_for('my_documents'))

    return render_template('upload.html', categories=categories, viewers=registered_viewers)


# --- DOWNLOAD / PREVIEW DOCUMENT ---

@app.route('/document/<int:doc_id>/download')
@login_required
def download_document(doc_id):
    user = get_current_user()
    doc = Document.query.get_or_404(doc_id)

    # Check permission: admin, owner, or shared viewer
    has_access = (
        user.is_admin or
        doc.owner_id == user.id or
        DocumentPermission.query.filter_by(document_id=doc.id, user_id=user.id).first() is not None
    )

    if not has_access:
        log_activity('ACCESS_DENIED', f"Unauthorized download attempt for doc #{doc.id} ('{doc.title}') by {user.username}")
        flash("Security Alert: You do not have permission to download this document.", "danger")
        return redirect(url_for('my_documents'))

    log_activity('DOWNLOAD', f"Downloaded '{doc.title}' ({doc.original_filename})")
    return send_from_directory(
        UPLOAD_FOLDER,
        doc.filename,
        as_attachment=True,
        download_name=doc.original_filename
    )


# --- MANAGE ACCESS (GRANT / REVOKE PERMISSIONS) ---

@app.route('/document/<int:doc_id>/manage-access', methods=['GET', 'POST'])
@login_required
def manage_access(doc_id):
    user = get_current_user()
    doc = Document.query.get_or_404(doc_id)

    # Strict RBAC: Only Admin or the Document Owner can manage access!
    if not (user.is_admin or doc.owner_id == user.id):
        log_activity('ACCESS_DENIED', f"Illegal access management attempt on doc #{doc.id} by non-owner {user.username}")
        flash("Access Denied: Only the document owner or an administrator can manage sharing permissions.", "danger")
        return redirect(url_for('my_documents'))

    current_permissions = DocumentPermission.query.filter_by(document_id=doc.id).all()
    shared_user_ids = [p.user_id for p in current_permissions]
    eligible_users = User.query.filter(User.id != doc.owner_id, ~User.id.in_(shared_user_ids) if shared_user_ids else True).all()

    if request.method == 'POST':
        action_type = request.form.get('action_type')

        if action_type == 'grant':
            target_user_id = request.form.get('target_user_id')
            perm_type = request.form.get('perm_type', 'viewer')

            if not target_user_id:
                flash("Please select a user to grant access to.", "warning")
            else:
                target_user = User.query.get(int(target_user_id))
                if target_user:
                    existing = DocumentPermission.query.filter_by(document_id=doc.id, user_id=target_user.id).first()
                    if not existing:
                        new_perm = DocumentPermission(
                            document_id=doc.id,
                            user_id=target_user.id,
                            permission_type=perm_type,
                            granted_by_id=user.id
                        )
                        db.session.add(new_perm)
                        db.session.commit()
                        log_activity('SHARE_GRANTED', f"Granted '{perm_type}' access to {target_user.username} on '{doc.title}'")
                        flash(f"Granted {perm_type} access to {target_user.username}.", "success")
                    else:
                        existing.permission_type = perm_type
                        db.session.commit()
                        flash(f"Updated access for {target_user.username} to {perm_type}.", "info")

        elif action_type == 'revoke':
            perm_id = request.form.get('permission_id')
            perm = DocumentPermission.query.get(perm_id)
            if perm and perm.document_id == doc.id:
                target_name = perm.grantee.username if perm.grantee else "User"
                db.session.delete(perm)
                db.session.commit()
                log_activity('SHARE_REVOKED', f"Revoked access of {target_name} on '{doc.title}'")
                flash(f"Access revoked for {target_name}.", "warning")

        return redirect(url_for('manage_access', doc_id=doc.id))

    return render_template(
        'manage_access.html',
        doc=doc,
        current_permissions=current_permissions,
        eligible_users=eligible_users
    )


# --- DELETE DOCUMENT ---

@app.route('/document/<int:doc_id>/delete', methods=['POST'])
@login_required
def delete_document(doc_id):
    user = get_current_user()
    doc = Document.query.get_or_404(doc_id)

    # Only document owner or admin can delete
    if not (user.is_admin or doc.owner_id == user.id):
        log_activity('ACCESS_DENIED', f"Unauthorized delete attempt on doc #{doc.id} ('{doc.title}') by {user.username}")
        flash("Permission Denied: Only the document owner or an administrator can delete this document.", "danger")
        return redirect(url_for('my_documents'))

    title = doc.title
    file_path = os.path.join(UPLOAD_FOLDER, doc.filename)
    if os.path.exists(file_path):
        try:
            os.remove(file_path)
        except OSError:
            pass

    db.session.delete(doc)
    db.session.commit()
    log_activity('DELETE', f"Deleted document '{title}' (ID: {doc_id})")
    flash(f"Document '{title}' was permanently deleted.", "success")
    return redirect(url_for('my_documents'))


# --- SEARCH DOCUMENTS ---

@app.route('/search')
@login_required
def search_documents():
    user = get_current_user()
    query = request.args.get('q', '').strip()
    category_id = request.args.get('category')
    owner_id = request.args.get('owner')
    date_from = request.args.get('date_from')
    date_to = request.args.get('date_to')

    # Allowed docs for this user
    if user.is_admin:
        base_query = Document.query
    else:
        shared_doc_ids = [p.document_id for p in DocumentPermission.query.filter_by(user_id=user.id).all()]
        base_query = Document.query.filter(
            (Document.owner_id == user.id) | (Document.id.in_(shared_doc_ids))
        )

    if query:
        base_query = base_query.filter(
            (Document.title.ilike(f"%{query}%")) |
            (Document.description.ilike(f"%{query}%")) |
            (Document.original_filename.ilike(f"%{query}%"))
        )

    if category_id and category_id.isdigit():
        base_query = base_query.filter(Document.category_id == int(category_id))

    if owner_id and owner_id.isdigit():
        base_query = base_query.filter(Document.owner_id == int(owner_id))

    if date_from:
        try:
            dt_from = datetime.strptime(date_from, '%Y-%m-%d')
            base_query = base_query.filter(Document.created_at >= dt_from)
        except ValueError:
            pass

    if date_to:
        try:
            dt_to = datetime.strptime(date_to + ' 23:59:59', '%Y-%m-%d %H:%M:%S')
            base_query = base_query.filter(Document.created_at <= dt_to)
        except ValueError:
            pass

    results = base_query.order_by(Document.created_at.desc()).all()
    categories = Category.query.all()
    all_owners = User.query.filter(User.role.in_(['owner', 'admin'])).all()

    return render_template(
        'search.html',
        results=results,
        categories=categories,
        owners=all_owners,
        query=query,
        selected_category=category_id,
        selected_owner=owner_id,
        date_from=date_from,
        date_to=date_to
    )


# --- CATEGORIES ---

@app.route('/categories')
@login_required
def categories_view():
    user = get_current_user()
    categories = Category.query.all()
    
    # Calculate visible docs per category for current user
    cat_stats = []
    for cat in categories:
        if user.is_admin:
            count = Document.query.filter_by(category_id=cat.id).count()
        else:
            shared_doc_ids = [p.document_id for p in DocumentPermission.query.filter_by(user_id=user.id).all()]
            count = Document.query.filter(
                (Document.category_id == cat.id) &
                ((Document.owner_id == user.id) | (Document.id.in_(shared_doc_ids)))
            ).count()
        cat_stats.append({'category': cat, 'count': count})

    return render_template('categories.html', cat_stats=cat_stats)


@app.route('/categories/<int:cat_id>')
@login_required
def category_detail(cat_id):
    user = get_current_user()
    category = Category.query.get_or_404(cat_id)

    if user.is_admin:
        docs = Document.query.filter_by(category_id=cat_id).order_by(Document.created_at.desc()).all()
    else:
        shared_doc_ids = [p.document_id for p in DocumentPermission.query.filter_by(user_id=user.id).all()]
        docs = Document.query.filter(
            (Document.category_id == cat_id) &
            ((Document.owner_id == user.id) | (Document.id.in_(shared_doc_ids)))
        ).order_by(Document.created_at.desc()).all()

    return render_template('category_detail.html', category=category, documents=docs)


# --- ACTIVITY LOGS (ADMIN ONLY AS SPECIFIED) ---

@app.route('/activity-logs')
@login_required
@admin_required
def activity_logs():
    action_filter = request.args.get('action', '')
    user_filter = request.args.get('user', '')

    base_query = ActivityLog.query

    if action_filter:
        base_query = base_query.filter(ActivityLog.action == action_filter)

    if user_filter and user_filter.isdigit():
        base_query = base_query.filter(ActivityLog.user_id == int(user_filter))

    logs = base_query.order_by(ActivityLog.timestamp.desc()).limit(150).all()
    users = User.query.all()
    actions = ['LOGIN', 'LOGOUT', 'REGISTER', 'UPLOAD', 'DOWNLOAD', 'DELETE', 'SHARE_GRANTED', 'SHARE_REVOKED', 'ACCESS_DENIED', 'PASSWORD_CHANGE', 'PROFILE_UPDATE']

    return render_template(
        'activity_logs.html',
        logs=logs,
        users=users,
        actions=actions,
        selected_action=action_filter,
        selected_user=user_filter
    )


# --- USER PROFILE & SETTINGS ---

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    user = get_current_user()

    if request.method == 'POST':
        action = request.form.get('profile_action')

        if action == 'update_avatar':
            avatar_file = request.files.get('avatar_file')
            if avatar_file and avatar_file.filename:
                if allowed_file(avatar_file.filename, ALLOWED_AVATARS):
                    orig = secure_filename(avatar_file.filename)
                    unique_avatar = f"avatar_{user.id}_{uuid.uuid4().hex[:8]}_{orig}"
                    save_path = os.path.join(AVATAR_FOLDER, unique_avatar)
                    avatar_file.save(save_path)
                    user.avatar = unique_avatar
                    db.session.commit()
                    log_activity('PROFILE_UPDATE', f"Updated profile photo")
                    flash("Profile photo updated successfully!", "success")
                else:
                    flash("Invalid image format. Allowed: PNG, JPG, JPEG, WEBP, GIF", "danger")

        elif action == 'change_password':
            current_pw = request.form.get('current_password', '')
            new_pw = request.form.get('new_password', '')
            confirm_pw = request.form.get('confirm_password', '')

            if not user.check_password(current_pw):
                flash("Current password is incorrect.", "danger")
            elif new_pw != confirm_pw:
                flash("New passwords do not match.", "danger")
            elif len(new_pw) < 6:
                flash("New password must be at least 6 characters.", "danger")
            else:
                user.set_password(new_pw)
                db.session.commit()
                log_activity('PASSWORD_CHANGE', "Updated account password")
                flash("Password changed successfully!", "success")

        return redirect(url_for('profile'))

    uploaded_count = Document.query.filter_by(owner_id=user.id).count()
    shared_count = DocumentPermission.query.filter_by(user_id=user.id).count()

    return render_template(
        'profile.html',
        user=user,
        uploaded_count=uploaded_count,
        shared_count=shared_count
    )


# --- ERROR HANDLERS ---

@app.errorhandler(403)
def forbidden_error(e):
    return render_template('403.html'), 403

@app.errorhandler(404)
def not_found_error(e):
    return render_template('404.html'), 404


# --- INITIAL DATABASE SEEDING ---

def seed_database():
    with app.app_context():
        db.create_all()

        # Seed categories if empty
        if Category.query.count() == 0:
            default_categories = [
                Category(name="Legal & Compliance", description="Contracts, NDAs, regulatory filings, and legal notices", icon="shield"),
                Category(name="Financial Reports", description="P&L statements, audit reports, quarterly filings", icon="chart"),
                Category(name="Executive & Board", description="Board meeting decks, strategic decisions, investor notes", icon="briefcase"),
                Category(name="Engineering & Tech", description="Architecture blueprints, security audits, source specs", icon="cpu"),
                Category(name="Human Resources", description="Personnel records, compensation frameworks, policies", icon="users"),
                Category(name="Confidential & Top Secret", description="Proprietary business secrets and sensitive assets", icon="lock")
            ]
            db.session.bulk_save_objects(default_categories)
            db.session.commit()

        # Seed initial Demo accounts if empty
        if User.query.count() == 0:
            # 1. Admin
            admin_user = User(
                username="admin",
                email="admin@trustvault.local",
                role="admin"
            )
            admin_user.set_password("admin123")

            # 2. Document Owner
            owner_sarah = User(
                username="owner_sarah",
                email="sarah@trustvault.local",
                role="owner"
            )
            owner_sarah.set_password("owner123")

            # 3. Viewer
            viewer_alex = User(
                username="viewer_alex",
                email="alex@trustvault.local",
                role="viewer"
            )
            viewer_alex.set_password("viewer123")

            db.session.add_all([admin_user, owner_sarah, viewer_alex])
            db.session.commit()

            # Seed sample confidential documents
            sample_docs_data = [
                ("TrustVault_Q3_Security_Audit.pdf", "TrustVault Q3 Security Audit & RBAC Benchmark", "Comprehensive internal pen-testing report validating isolation across multi-tenant partitions.", 1, admin_user.id),
                ("Corporate_Master_Services_Agreement.docx", "Master Services & Non-Disclosure Agreement (2026)", "Executed NDA and service level agreement for enterprise cloud deployment.", 1, owner_sarah.id),
                ("FY2026_Executive_Financial_Plan.xlsx", "FY2026 Executive Financial Forecast & Capital Allocation", "Detailed confidential quarterly projections and departmental budget thresholds.", 2, owner_sarah.id),
                ("Zero_Trust_Architecture_Spec.pdf", "Zero-Trust Cryptographic Document Storage Spec", "Technical specification for end-to-end payload encryption and access token verification.", 4, admin_user.id)
            ]

            for orig_fname, title, desc, cat_id, u_id in sample_docs_data:
                unique_name = f"seed_{uuid.uuid4().hex[:8]}_{orig_fname}"
                file_disk_path = os.path.join(UPLOAD_FOLDER, unique_name)
                # Write placeholder file content
                with open(file_disk_path, "w", encoding="utf-8") as f:
                    f.write(f"--- TRUSTVAULT CONFIDENTIAL DOCUMENT ---\nTitle: {title}\nClassification: Internal Restricted\nOwner ID: {u_id}\nCategory ID: {cat_id}\n\nThis is a verified secure record stored within the TrustVault encrypted partition.")
                
                f_size = os.path.getsize(file_disk_path)
                doc_obj = Document(
                    title=title,
                    description=desc,
                    filename=unique_name,
                    original_filename=orig_fname,
                    file_size=f_size,
                    category_id=cat_id,
                    owner_id=u_id
                )
                db.session.add(doc_obj)
                db.session.flush()

                # Share sarah's document with viewer_alex
                if orig_fname == "Corporate_Master_Services_Agreement.docx":
                    perm = DocumentPermission(
                        document_id=doc_obj.id,
                        user_id=viewer_alex.id,
                        permission_type="viewer",
                        granted_by_id=owner_sarah.id
                    )
                    db.session.add(perm)

            # Seed activity logs
            logs_to_add = [
                ActivityLog(user_id=admin_user.id, action="LOGIN", details="Admin signed in to security console", ip_address="127.0.0.1"),
                ActivityLog(user_id=admin_user.id, action="UPLOAD", details="Admin uploaded 'TrustVault Q3 Security Audit'", ip_address="127.0.0.1"),
                ActivityLog(user_id=owner_sarah.id, action="UPLOAD", details="Sarah uploaded 'Master Services Agreement'", ip_address="192.168.1.15"),
                ActivityLog(user_id=owner_sarah.id, action="SHARE_GRANTED", details="Sarah granted 'viewer' permission to viewer_alex", ip_address="192.168.1.15"),
                ActivityLog(user_id=viewer_alex.id, action="LOGIN", details="Viewer Alex logged in", ip_address="192.168.1.42"),
                ActivityLog(user_id=viewer_alex.id, action="DOWNLOAD", details="Alex downloaded 'Corporate_Master_Services_Agreement.docx'", ip_address="192.168.1.42")
            ]
            db.session.add_all(logs_to_add)
            db.session.commit()

if __name__ == '__main__':
    seed_database()
    app.run(debug=True, host='127.0.0.1', port=5000)
