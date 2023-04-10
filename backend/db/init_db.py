import os
import sqlite3

def init_db():
    connection = sqlite3.connect('storage/database.db')
    with open('db/schema.sql') as f:
        connection.executescript(f.read())
    SHOULD_DECOMPILE = 1
    SHOULD_USE_MOBSF = 1
    connection.execute('INSERT INTO Config(ENV,SHOULD_DECOMPILE,SHOULD_USE_MOBSF) SELECT "production",?,? WHERE NOT EXISTS (SELECT ENV FROM Config WHERE ENV = "production")',(SHOULD_DECOMPILE,SHOULD_USE_MOBSF,))
    connection.commit()
    connection.close()