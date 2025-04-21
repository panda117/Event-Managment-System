from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()

# Event registrations
event_registrations = db.Table('event_registrations',
    db.Column('user_id', db.Integer, db.ForeignKey('user.id'), primary_key=True),
    db.Column('event_id', db.Integer, db.ForeignKey('event.id'), primary_key=True)
)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256))
    bio = db.Column(db.Text)
    avatar = db.Column(db.String(200))  # Path to avatar image
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_seen = db.Column(db.DateTime, default=datetime.utcnow)
    is_admin = db.Column(db.Boolean, default=False)
    dark_mode = db.Column(db.Boolean, default=False)
    
    # Relationships
    created_events = db.relationship('Event', backref='organizer', lazy='dynamic', foreign_keys='Event.organizer_id')
    comments = db.relationship('Comment', backref='author', lazy='dynamic')
    events = db.relationship('Event', secondary=event_registrations, 
                             backref=db.backref('attendees', lazy='dynamic'))
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
        
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def __repr__(self):
        return f'<User {self.username}>'

class Category(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)
    description = db.Column(db.Text)
    color = db.Column(db.String(7), default="#607D8B")  # Default color code
    
    # Events in this category
    events = db.relationship('Event', backref='category', lazy='dynamic')
    
    def __repr__(self):
        return f'<Category {self.name}>'
    
class Event(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    location = db.Column(db.String(200), nullable=False)
    address = db.Column(db.String(200))
    latitude = db.Column(db.Float)
    longitude = db.Column(db.Float)
    start_time = db.Column(db.DateTime, nullable=False)
    end_time = db.Column(db.DateTime, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    capacity = db.Column(db.Integer)
    is_private = db.Column(db.Boolean, default=False)
    image = db.Column(db.String(200))  # Path to event image
    organizer_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    category_id = db.Column(db.Integer, db.ForeignKey('category.id'), nullable=False)
    
    # Relationships
    comments = db.relationship('Comment', backref='event', lazy='dynamic', cascade='all, delete-orphan')
    
    def registration_count(self):
        return self.attendees.count()
    
    def is_full(self):
        if self.capacity:
            return self.registration_count() >= self.capacity
        return False
    
    def is_upcoming(self):
        return self.start_time > datetime.utcnow()
    
    def is_ongoing(self):
        now = datetime.utcnow()
        return self.start_time <= now <= self.end_time
    
    def is_past(self):
        return self.end_time < datetime.utcnow()
    
    def __repr__(self):
        return f'<Event {self.title}>'

class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    event_id = db.Column(db.Integer, db.ForeignKey('event.id'), nullable=False)
    
    def __repr__(self):
        return f'<Comment {self.id}>'

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    recipient_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    is_read = db.Column(db.Boolean, default=False)
    
    # Define relationships
    sender = db.relationship('User', foreign_keys=[sender_id])
    recipient = db.relationship('User', foreign_keys=[recipient_id])
    
    def __repr__(self):
        return f'<Message {self.id}>'