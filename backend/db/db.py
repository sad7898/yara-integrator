import sqlite3
import os
DATABASE = os.path.join("storage","database.db")
db = None
def get_db():
    global db
    if db is None:
        db = sqlite3.connect(DATABASE,check_same_thread=False)
    return db
