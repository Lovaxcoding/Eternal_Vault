import awsgi
from app import create_app

# Initialisation de ton application Flask
app = create_app()

def handler(event, context):
    return awsgi.response(app, event, context)