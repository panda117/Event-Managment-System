from app import app, create_tables

# Initialize database in application context
with app.app_context():
    create_tables()