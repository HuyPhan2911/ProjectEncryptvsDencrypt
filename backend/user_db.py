"""
In-memory user database.
Simple user storage for the OAuth2 demo.
"""
# In-memory user database
users = [
    {
        "id": "user1",
        "username": "alice",
        "password": "password123",  # In production, use hashed passwords!
        "email": "alice@example.com"
    },
    {
        "id": "user2",
        "username": "bob",
        "password": "password123",
        "email": "bob@example.com"
    }
]


def verify_user_credentials(username: str, password: str):
    """
    Verify user credentials against the user database.
    Returns user dict if valid, None otherwise.
    """
    for user in users:
        if user['username'] == username and user['password'] == password:
            return user
            
    return None


def get_user_by_id(user_id: str):
    """
    Get user by ID from the user database.
    Returns user dict if found, None otherwise.
    """
    for user in users:
        if user['id'] == user_id:
            return user
    return None

