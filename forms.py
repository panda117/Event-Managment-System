from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed
from wtforms import StringField, PasswordField, BooleanField, TextAreaField, SelectField, DateTimeField, IntegerField, FloatField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError, Optional, NumberRange
from datetime import datetime
from models import User, Category

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember_me = BooleanField('Remember Me')

class AdminLoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember_me = BooleanField('Remember Me')
    
    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if not user or not user.is_admin:
            raise ValidationError('Please enter a valid admin email address.')

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=20)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirm Password', 
                                    validators=[DataRequired(), EqualTo('password')])
    
    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('That username is already taken. Please choose a different one.')
    
    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('That email is already registered. Please use a different one.')

class UpdateProfileForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=20)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    bio = TextAreaField('Bio', validators=[Length(max=500)])
    avatar = FileField('Update Profile Picture', validators=[FileAllowed(['jpg', 'png', 'jpeg'])])
    dark_mode = BooleanField('Dark Mode')
    
    def __init__(self, original_username, original_email, *args, **kwargs):
        super(UpdateProfileForm, self).__init__(*args, **kwargs)
        self.original_username = original_username
        self.original_email = original_email
    
    def validate_username(self, username):
        if username.data != self.original_username:
            user = User.query.filter_by(username=username.data).first()
            if user:
                raise ValidationError('That username is already taken. Please choose a different one.')
    
    def validate_email(self, email):
        if email.data != self.original_email:
            user = User.query.filter_by(email=email.data).first()
            if user:
                raise ValidationError('That email is already registered. Please use a different one.')

class EventForm(FlaskForm):
    title = StringField('Event Title', validators=[DataRequired(), Length(min=5, max=100)])
    description = TextAreaField('Description', validators=[DataRequired()])
    location = StringField('Location Name', validators=[DataRequired(), Length(max=200)])
    address = StringField('Address', validators=[Length(max=200)])
    latitude = FloatField('Latitude', validators=[Optional()])
    longitude = FloatField('Longitude', validators=[Optional()])
    start_time = DateTimeField('Start Time', format='%Y-%m-%dT%H:%M', validators=[DataRequired()])
    end_time = DateTimeField('End Time', format='%Y-%m-%dT%H:%M', validators=[DataRequired()])
    capacity = IntegerField('Capacity (optional)', validators=[Optional(), NumberRange(min=1)])
    is_private = BooleanField('Private Event')
    image = FileField('Event Image', validators=[FileAllowed(['jpg', 'png', 'jpeg'])])
    category = SelectField('Category', coerce=int, validators=[DataRequired()])
    
    def validate_end_time(self, end_time):
        if end_time.data <= self.start_time.data:
            raise ValidationError('End time must be after start time.')
        
    def validate_start_time(self, start_time):
        if start_time.data < datetime.utcnow():
            raise ValidationError('Start time cannot be in the past.')

class CommentForm(FlaskForm):
    content = TextAreaField('Comment', validators=[DataRequired(), Length(min=1, max=500)])

class MessageForm(FlaskForm):
    content = TextAreaField('Message', validators=[DataRequired(), Length(min=1, max=2000)])

class CategoryForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired(), Length(max=50)])
    description = TextAreaField('Description', validators=[Length(max=500)])
    color = StringField('Color (HEX)', validators=[DataRequired(), Length(min=4, max=7)])

class SearchForm(FlaskForm):
    query = StringField('Search', validators=[DataRequired()])
    search_type = SelectField('Type', choices=[
        ('events', 'Events'), 
        ('users', 'Users'), 
        ('categories', 'Categories')
    ], default='events')