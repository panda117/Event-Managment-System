import os
import logging
from datetime import datetime
from functools import wraps
from sqlalchemy import or_
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash

from flask import Flask, render_template, flash, redirect, url_for, request, abort, jsonify, g, session
from flask_login import LoginManager, current_user, login_user, logout_user, login_required, UserMixin
from werkzeug.middleware.proxy_fix import ProxyFix

# Configure logging
logging.basicConfig(level=logging.DEBUG)

# Create Flask application
app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET")
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)  # needed for url_for to generate with https

# Configure SQLAlchemy
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL")
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_recycle": 300,
    "pool_pre_ping": True,
}
app.config["WTF_CSRF_ENABLED"] = True

# Import models and db instance
from models import db, User, Category, Event, Comment, Message, event_registrations

# Initialize SQLAlchemy with app
db.init_app(app)

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'

# Initialize Flask-WTF CSRF protection
from flask_wtf.csrf import CSRFProtect
csrf = CSRFProtect(app)

# Register the Google Auth blueprint
from google_auth import google_auth
app.register_blueprint(google_auth)

# Setup Login Manager user_loader
@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

# Decorator to require admin role
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            flash('You need administrator privileges to access this page.', 'danger')
            return redirect(url_for('home'))
        return f(*args, **kwargs)
    return decorated_function

# Helper function to save uploaded files
def save_file(form_file, folder='uploads'):
    if form_file.filename:
        filename = secure_filename(form_file.filename)
        # Generate unique filename with timestamp
        timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
        unique_filename = f"{timestamp}_{filename}"
        # Ensure directory exists
        path = os.path.join('static', folder)
        os.makedirs(path, exist_ok=True)
        filepath = os.path.join(path, unique_filename)
        form_file.save(filepath)
        return os.path.join(folder, unique_filename)
    return None

# Routes
@app.route('/')
def home():
    page = request.args.get('page', 1, type=int)
    # Get upcoming events with pagination
    events = Event.query.filter(
        Event.end_time > datetime.utcnow(),
        or_(Event.is_private == False, 
            Event.organizer_id == getattr(current_user, 'id', None))
    ).order_by(Event.start_time).paginate(page=page, per_page=9)
    
    categories = Category.query.all()
    return render_template('home.html', events=events, categories=categories)

@app.route('/calendar')
def calendar():
    categories = Category.query.all()
    return render_template('calendar.html', categories=categories)

@app.route('/api/events')
def events_api():
    """API endpoint for calendar events"""
    # Get date range filters from request
    start = request.args.get('start')
    end = request.args.get('end')
    category_id = request.args.get('category_id', type=int)
    
    # Build query
    query = Event.query
    
    # Apply date range filter if provided
    if start and end:
        query = query.filter(Event.end_time >= start, Event.start_time <= end)
    
    # Apply category filter if provided
    if category_id:
        query = query.filter(Event.category_id == category_id)
    
    # Apply privacy filter
    if not current_user.is_authenticated:
        query = query.filter(Event.is_private == False)
    else:
        # Show private events only if the user is the organizer
        query = query.filter(
            or_(Event.is_private == False, 
                Event.organizer_id == current_user.id)
        )
    
    # Get events
    events = query.all()
    
    # Format events for FullCalendar
    result = []
    for event in events:
        result.append({
            'id': event.id,
            'title': event.title,
            'start': event.start_time.isoformat(),
            'end': event.end_time.isoformat(),
            'url': url_for('event', event_id=event.id),
            'location': event.location,
            'color': event.category.color,
            'extendedProps': {
                'location': event.location,
                'organizer': event.organizer.username,
                'category': event.category.name,
                'is_private': event.is_private
            }
        })
    
    return jsonify(result)

# Import forms
from forms import RegistrationForm, LoginForm, AdminLoginForm, UpdateProfileForm, EventForm, CommentForm, MessageForm, CategoryForm, SearchForm

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    
    form = RegistrationForm()
    if form.validate_on_submit():
        # Hash password
        hashed_password = generate_password_hash(form.password.data)
        
        # Create new user
        user = User(
            username=form.username.data,
            email=form.email.data,
            password_hash=hashed_password
        )
        
        # Make first user an admin
        if User.query.count() == 0:
            user.is_admin = True
        
        # Add to database
        db.session.add(user)
        db.session.commit()
        
        flash('Your account has been created! You can now log in.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        
        # Check if user exists and password is correct
        if user and check_password_hash(user.password_hash, form.password.data):
            login_user(user, remember=form.remember_me.data)
            # Update last seen time
            user.last_seen = datetime.utcnow()
            db.session.commit()
            
            # Redirect to originally requested page if it exists
            next_page = request.args.get('next')
            if next_page:
                return redirect(next_page)
            return redirect(url_for('home'))
        else:
            flash('Login failed. Please check your email and password.', 'danger')
    
    return render_template('login.html', form=form)

@app.route('/logout')
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('home'))

@app.route('/profile/<username>')
def profile(username):
    user = User.query.filter_by(username=username).first_or_404()
    
    # Get user's events (created and attending)
    created_events = Event.query.filter_by(organizer_id=user.id).order_by(Event.start_time.desc()).all()
    
    # Only show attended events for the user's own profile or for public events
    if current_user.is_authenticated and current_user.id == user.id:
        attended_events = user.events
    else:
        # For other users, only show non-private events they're attending
        attended_events = [event for event in user.events if not event.is_private]
    
    return render_template('profile.html', user=user, created_events=created_events, attended_events=attended_events)

@app.route('/profile/update', methods=['GET', 'POST'])
@login_required
def update_profile():
    form = UpdateProfileForm(current_user.username, current_user.email)
    
    if form.validate_on_submit():
        # Process avatar if uploaded
        if form.avatar.data:
            avatar_file = save_file(form.avatar.data, 'uploads/avatars')
            current_user.avatar = avatar_file
        
        # Update user details
        current_user.username = form.username.data
        current_user.email = form.email.data
        current_user.bio = form.bio.data
        current_user.dark_mode = form.dark_mode.data
        
        db.session.commit()
        flash('Your profile has been updated!', 'success')
        return redirect(url_for('profile', username=current_user.username))
    
    # Pre-populate form
    elif request.method == 'GET':
        form.username.data = current_user.username
        form.email.data = current_user.email
        form.bio.data = current_user.bio
        form.dark_mode.data = current_user.dark_mode
    
    return render_template('update_profile.html', form=form)

@app.route('/category/<int:category_id>')
def category(category_id):
    category = Category.query.get_or_404(category_id)
    page = request.args.get('page', 1, type=int)
    
    # Get category events with pagination
    if current_user.is_authenticated:
        events = Event.query.filter(
            Event.category_id == category_id,
            or_(Event.is_private == False, Event.organizer_id == current_user.id)
        ).order_by(Event.start_time).paginate(page=page, per_page=9)
    else:
        events = Event.query.filter_by(
            category_id=category_id, is_private=False
        ).order_by(Event.start_time).paginate(page=page, per_page=9)
    
    categories = Category.query.all()
    return render_template('home.html', events=events, categories=categories, current_category=category)

@app.route('/event/new', methods=['GET', 'POST'])
@login_required
def new_event():
    form = EventForm()
    
    # Populate category choices
    form.category.choices = [(c.id, c.name) for c in Category.query.order_by('name')]
    
    if form.validate_on_submit():
        # Process image if uploaded
        image_file = None
        if form.image.data:
            image_file = save_file(form.image.data, 'uploads/events')
        
        # Create new event
        event = Event(
            title=form.title.data,
            description=form.description.data,
            location=form.location.data,
            address=form.address.data,
            latitude=form.latitude.data,
            longitude=form.longitude.data,
            start_time=form.start_time.data,
            end_time=form.end_time.data,
            capacity=form.capacity.data,
            is_private=form.is_private.data,
            image=image_file,
            organizer_id=current_user.id,
            category_id=form.category.data
        )
        
        db.session.add(event)
        db.session.commit()
        
        flash('Your event has been created!', 'success')
        return redirect(url_for('event', event_id=event.id))
    
    return render_template('create_event.html', form=form, legend='Create Event')

@app.route('/event/<int:event_id>')
def event(event_id):
    event = Event.query.get_or_404(event_id)
    
    # Check if event is private and user is not the organizer
    if event.is_private and (not current_user.is_authenticated or current_user.id != event.organizer_id):
        if not current_user.is_authenticated or event not in current_user.events:
            flash('This is a private event. You need to be registered to view it.', 'warning')
            return redirect(url_for('home'))
    
    # Get comments for the event
    comments = Comment.query.filter_by(event_id=event.id).order_by(Comment.created_at.asc()).all()
    
    # Check if user is registered for this event
    is_registered = False
    if current_user.is_authenticated:
        is_registered = event in current_user.events
    
    # Create comment form
    form = CommentForm()
    
    return render_template(
        'event.html', 
        event=event, 
        comments=comments, 
        is_registered=is_registered, 
        form=form,
        google_maps_api_key=os.environ.get('GOOGLE_MAPS_API_KEY', '')
    )

@app.route('/event/<int:event_id>/update', methods=['GET', 'POST'])
@login_required
def update_event(event_id):
    event = Event.query.get_or_404(event_id)
    
    # Check if user is the organizer
    if event.organizer_id != current_user.id and not current_user.is_admin:
        abort(403)
    
    form = EventForm()
    
    # Populate category choices
    form.category.choices = [(c.id, c.name) for c in Category.query.order_by('name')]
    
    if form.validate_on_submit():
        # Update event details
        event.title = form.title.data
        event.description = form.description.data
        event.location = form.location.data
        event.address = form.address.data
        event.latitude = form.latitude.data
        event.longitude = form.longitude.data
        event.start_time = form.start_time.data
        event.end_time = form.end_time.data
        event.capacity = form.capacity.data
        event.is_private = form.is_private.data
        event.category_id = form.category.data
        
        # Process image if uploaded
        if form.image.data:
            image_file = save_file(form.image.data, 'uploads/events')
            event.image = image_file
        
        # Update timestamp
        event.updated_at = datetime.utcnow()
        
        db.session.commit()
        flash('Your event has been updated!', 'success')
        return redirect(url_for('event', event_id=event.id))
    
    # Pre-populate form
    elif request.method == 'GET':
        form.title.data = event.title
        form.description.data = event.description
        form.location.data = event.location
        form.address.data = event.address
        form.latitude.data = event.latitude
        form.longitude.data = event.longitude
        form.start_time.data = event.start_time
        form.end_time.data = event.end_time
        form.capacity.data = event.capacity
        form.is_private.data = event.is_private
        form.category.data = event.category_id
    
    return render_template('create_event.html', form=form, legend='Update Event', google_maps_api_key=os.environ.get('GOOGLE_MAPS_API_KEY', ''))

@app.route('/event/<int:event_id>/delete', methods=['POST'])
@login_required
def delete_event(event_id):
    event = Event.query.get_or_404(event_id)
    
    # Check if user is the organizer
    if event.organizer_id != current_user.id and not current_user.is_admin:
        abort(403)
    
    # Delete the event
    db.session.delete(event)
    db.session.commit()
    
    flash('Your event has been deleted!', 'success')
    return redirect(url_for('home'))

@app.route('/event/<int:event_id>/comment', methods=['POST'])
@login_required
def add_comment(event_id):
    event = Event.query.get_or_404(event_id)
    form = CommentForm()
    
    if form.validate_on_submit():
        # Create new comment
        comment = Comment(
            content=form.content.data,
            user_id=current_user.id,
            event_id=event.id
        )
        
        db.session.add(comment)
        db.session.commit()
        
        flash('Your comment has been posted!', 'success')
    
    return redirect(url_for('event', event_id=event.id))

@app.route('/event/<int:event_id>/register', methods=['POST'])
@login_required
def register_event(event_id):
    event = Event.query.get_or_404(event_id)
    
    # Check if event is full
    if event.is_full():
        flash('Sorry, this event is already full.', 'warning')
        return redirect(url_for('event', event_id=event.id))
    
    # Check if user is already registered
    if event in current_user.events:
        flash('You are already registered for this event.', 'info')
        return redirect(url_for('event', event_id=event.id))
    
    # Register user for event
    current_user.events.append(event)
    db.session.commit()
    
    flash('You have successfully registered for this event!', 'success')
    return redirect(url_for('event', event_id=event.id))

@app.route('/event/<int:event_id>/unregister', methods=['POST'])
@login_required
def unregister_event(event_id):
    event = Event.query.get_or_404(event_id)
    
    # Check if user is registered
    if event not in current_user.events:
        flash('You are not registered for this event.', 'info')
        return redirect(url_for('event', event_id=event.id))
    
    # Unregister user from event
    current_user.events.remove(event)
    db.session.commit()
    
    flash('You have unregistered from this event.', 'info')
    return redirect(url_for('event', event_id=event.id))

@app.route('/messages')
@login_required
def messages():
    # Get users the current user has conversations with
    user_conversations = db.session.query(User).join(
        Message, 
        ((Message.sender_id == User.id) & (Message.recipient_id == current_user.id)) | 
        ((Message.recipient_id == User.id) & (Message.sender_id == current_user.id))
    ).distinct().all()
    
    return render_template('messages.html', conversations=user_conversations)

@app.route('/messages/<int:user_id>', methods=['GET', 'POST'])
@login_required
def conversation(user_id):
    other_user = User.query.get_or_404(user_id)
    
    # Don't allow messaging yourself
    if user_id == current_user.id:
        flash('You cannot message yourself.', 'warning')
        return redirect(url_for('messages'))
    
    form = MessageForm()
    
    if form.validate_on_submit():
        # Create new message
        message = Message(
            content=form.content.data,
            sender_id=current_user.id,
            recipient_id=user_id
        )
        
        db.session.add(message)
        db.session.commit()
        
        flash('Your message has been sent!', 'success')
        return redirect(url_for('conversation', user_id=user_id))
    
    # Get conversation messages
    messages = Message.query.filter(
        ((Message.sender_id == current_user.id) & (Message.recipient_id == user_id)) |
        ((Message.recipient_id == current_user.id) & (Message.sender_id == user_id))
    ).order_by(Message.created_at.asc()).all()
    
    # Mark unread messages as read
    unread_messages = Message.query.filter_by(
        recipient_id=current_user.id, 
        sender_id=user_id, 
        is_read=False
    ).all()
    
    for message in unread_messages:
        message.is_read = True
    
    db.session.commit()
    
    return render_template('conversation.html', other_user=other_user, messages=messages, form=form)

@app.route('/search')
def search():
    # Get search parameters
    query = request.args.get('query', '')
    search_type = request.args.get('search_type', 'events')
    
    if not query:
        return render_template('search.html', query=query, search_type=search_type, results=None)
    
    results = []
    
    # Search based on type
    if search_type == 'events':
        # Search in events
        if current_user.is_authenticated:
            results = Event.query.filter(
                Event.title.ilike(f'%{query}%') | 
                Event.description.ilike(f'%{query}%') | 
                Event.location.ilike(f'%{query}%'),
                or_(Event.is_private == False, Event.organizer_id == current_user.id)
            ).order_by(Event.start_time).all()
        else:
            results = Event.query.filter(
                Event.title.ilike(f'%{query}%') | 
                Event.description.ilike(f'%{query}%') | 
                Event.location.ilike(f'%{query}%'),
                Event.is_private == False
            ).order_by(Event.start_time).all()
    
    elif search_type == 'users':
        # Search in users
        results = User.query.filter(
            User.username.ilike(f'%{query}%')
        ).order_by(User.username).all()
    
    elif search_type == 'categories':
        # Search in categories
        results = Category.query.filter(
            Category.name.ilike(f'%{query}%') |
            Category.description.ilike(f'%{query}%')
        ).order_by(Category.name).all()
    
    return render_template('search.html', query=query, search_type=search_type, results=results)

# Admin routes
@app.route('/admin/categories')
@login_required
@admin_required
def admin_categories():
    categories = Category.query.order_by(Category.name).all()
    form = CategoryForm()
    
    return render_template('admin/categories.html', categories=categories, form=form)

@app.route('/admin/categories/edit/<int:category_id>', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_category(category_id):
    category = Category.query.get_or_404(category_id)
    form = CategoryForm()
    
    if form.validate_on_submit():
        # Update category
        category.name = form.name.data
        category.description = form.description.data
        category.color = form.color.data
        
        db.session.commit()
        flash('Category has been updated!', 'success')
        return redirect(url_for('admin_categories'))
    
    # Pre-populate form
    elif request.method == 'GET':
        form.name.data = category.name
        form.description.data = category.description
        form.color.data = category.color
    
    return render_template('admin/edit_category.html', form=form, category=category)

@app.route('/admin/categories/delete/<int:category_id>', methods=['POST'])
@login_required
@admin_required
def delete_category(category_id):
    category = Category.query.get_or_404(category_id)
    
    # Check if the category has events
    if category.events.count() > 0:
        flash('Cannot delete category with events. Reassign events first.', 'danger')
        return redirect(url_for('admin_categories'))
    
    # Delete the category
    db.session.delete(category)
    db.session.commit()
    
    flash('Category has been deleted!', 'success')
    return redirect(url_for('admin_categories'))

@app.route('/admin/users')
@login_required
@admin_required
def admin_users():
    users = User.query.order_by(User.username).all()
    return render_template('admin/users.html', users=users)

@app.route('/admin/users/toggle_admin/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def toggle_admin(user_id):
    user = User.query.get_or_404(user_id)
    
    # Prevent removing admin status from yourself
    if user.id == current_user.id:
        flash('You cannot remove your own admin status.', 'danger')
        return redirect(url_for('admin_users'))
    
    # Toggle admin status
    user.is_admin = not user.is_admin
    db.session.commit()
    
    flash(f'Admin status for {user.username} has been {"granted" if user.is_admin else "revoked"}.', 'success')
    return redirect(url_for('admin_users'))

# Admin routes
@app.route('/admin')
def admin_redirect():
    if current_user.is_authenticated and current_user.is_admin:
        return redirect(url_for('admin_dashboard'))
    return redirect(url_for('admin_login'))

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if current_user.is_authenticated:
        if current_user.is_admin:
            return redirect(url_for('admin_dashboard'))
        else:
            flash('You do not have administrator privileges.', 'danger')
            return redirect(url_for('home'))
    
    form = AdminLoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        
        # Check if user exists, is admin and password is correct
        if user and user.is_admin and check_password_hash(user.password_hash, form.password.data):
            login_user(user, remember=form.remember_me.data)
            # Update last seen time
            user.last_seen = datetime.utcnow()
            db.session.commit()
            
            flash('You have been logged in as administrator.', 'success')
            return redirect(url_for('admin_dashboard'))
        else:
            flash('Admin login failed. Please check your credentials.', 'danger')
    
    return render_template('admin/login.html', form=form)

@app.route('/admin/dashboard')
@login_required
@admin_required
def admin_dashboard():
    # Get counts for dashboard
    user_count = User.query.count()
    event_count = Event.query.count()
    category_count = Category.query.count()
    
    # Get recent activity (last 7 days)
    from datetime import timedelta
    one_week_ago = datetime.utcnow() - timedelta(days=7)
    recent_users_count = User.query.filter(User.created_at >= one_week_ago).count()
    recent_events_count = Event.query.filter(Event.created_at >= one_week_ago).count()
    
    return render_template(
        'admin/dashboard.html',
        user_count=user_count,
        event_count=event_count,
        category_count=category_count,
        recent_users_count=recent_users_count,
        recent_events_count=recent_events_count
    )

# Admin users route is already defined above

# admin_categories route is already defined above

@app.route('/admin/events')
@login_required
@admin_required
def admin_events():
    events = Event.query.order_by(Event.created_at.desc()).all()
    return render_template('admin/events.html', events=events)

@app.route('/admin/reports')
@login_required
@admin_required
def admin_reports():
    return render_template('admin/reports.html')

@app.route('/admin/settings')
@login_required
@admin_required
def admin_settings():
    return render_template('admin/settings.html')

@app.route('/admin/categories/new', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_categories_new():
    form = CategoryForm()
    
    if form.validate_on_submit():
        # Create new category
        category = Category(
            name=form.name.data,
            description=form.description.data,
            color=form.color.data
        )
        
        db.session.add(category)
        db.session.commit()
        
        flash('New category has been created!', 'success')
        return redirect(url_for('admin_categories'))
    
    return render_template('admin/new_category.html', form=form)

# Context processor to inject variables into all templates
@app.context_processor
def inject_base_context():
    """Inject variables to all templates."""
    context = {}
    
    # Add unread messages count for authenticated users
    if current_user.is_authenticated:
        unread_messages = Message.query.filter_by(recipient_id=current_user.id, is_read=False).count()
        context['unread_messages'] = unread_messages
    else:
        context['unread_messages'] = 0
    
    # Add Google Maps API key
    context['google_maps_api_key'] = os.environ.get('GOOGLE_MAPS_API_KEY', '')
    
    return context

# Error handlers
@app.errorhandler(404)
def not_found_error(error):
    return render_template('errors/404.html'), 404

@app.errorhandler(403)
def forbidden_error(error):
    return render_template('errors/403.html'), 403

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return render_template('errors/500.html'), 500

# Create database tables
def create_tables():
    db.create_all()
    
    # Create default categories if none exist
    if Category.query.count() == 0:
        categories = [
            Category(name='Conference', description='Professional conferences and meetups', color='#4e73df'),
            Category(name='Workshop', description='Hands-on learning sessions', color='#1cc88a'),
            Category(name='Social', description='Social gatherings and networking events', color='#36b9cc'),
            Category(name='Concert', description='Music performances and concerts', color='#f6c23e'),
            Category(name='Sports', description='Sporting events and tournaments', color='#e74a3b'),
            Category(name='Community', description='Community activities and volunteering', color='#858796'),
            Category(name='Other', description='Other event types', color='#5a5c69')
        ]
        
        for category in categories:
            db.session.add(category)
        
        db.session.commit()
        print("Default categories created.")
    
    # Create default admin user if no users exist
    if User.query.count() == 0:
        admin_password = generate_password_hash("admin123")
        admin_user = User(
            username="admin",
            email="admin@example.com",
            password_hash=admin_password,
            is_admin=True,
            bio="System administrator"
        )
        db.session.add(admin_user)
        db.session.commit()
        print("Default admin user created.")
        print("Username: admin@example.com")
        print("Password: admin123")
        print("Please change these credentials after first login.")

# Initialize app when executed directly
if __name__ == '__main__':
    with app.app_context():
        create_tables()
    
    app.run(debug=True, host='0.0.0.0')